"""Tests for per-metric downsample period overrides."""

import json
import subprocess
import sys
import threading
import urllib.error as urllib_error
import urllib.request as urllib_request
from http.server import ThreadingHTTPServer

import pytest

from metric_fusion import MetricBatchService, process


def sample(ts, source="a", name="cpu.usage", value=1.0, labels=None):
    return {
        "source": source,
        "name": name,
        "labels": {"host": "db-1"} if labels is None else labels,
        "timestamp_ms": ts,
        "value": value,
    }


def payload(metrics, **extra):
    request = {
        "downsample_ms": 1000,
        "suppression_ms": 0,
        "metrics": metrics,
        "alerts": [],
    }
    request.update(extra)
    return request


# -- process() ----------------------------------------------------------------


def test_override_rewindows_only_the_configured_metric():
    metrics = [
        sample(900, name="cpu.usage", value=1.0),
        sample(1100, name="cpu.usage", value=3.0),
        sample(900, name="mem.usage", value=10.0),
        sample(1100, name="mem.usage", value=30.0),
    ]
    result = process(payload(metrics, downsample_overrides={"cpu.usage": 2000}))
    by_name = {}
    for row in result["series"]:
        by_name.setdefault(row["name"], []).append(row)
    # cpu.usage: both samples fall into the same 2000ms window.
    assert [row["timestamp_ms"] for row in by_name["cpu.usage"]] == [0]
    assert by_name["cpu.usage"][0]["value"] == 2.0
    assert by_name["cpu.usage"][0]["count"] == 2
    # mem.usage: no override, the default 1000ms grid still applies.
    assert [row["timestamp_ms"] for row in by_name["mem.usage"]] == [0, 1000]


def test_override_windows_align_to_period_multiples():
    result = process(
        payload(
            [sample(1500, value=1.0), sample(2900, value=2.0), sample(3100, value=4.0)],
            downsample_overrides={"cpu.usage": 2000},
        )
    )
    assert [(row["timestamp_ms"], row["value"]) for row in result["series"]] == [
        (0, 1.0),
        (2000, 3.0),
    ]


def test_unmatched_or_absent_override_leaves_output_unchanged():
    without = process(payload([sample(0), sample(100)]))
    unmatched = process(
        payload([sample(0), sample(100)], downsample_overrides={"other": 50})
    )
    assert without["series"] == unmatched["series"]
    assert set(without) == {"series", "alerts", "suppressed_alert_ids"}


def test_override_applies_after_dedup_last_write_wins():
    result = process(
        payload(
            [
                sample(100, value=1.0),
                sample(100, value=9.0),  # same point: later occurrence wins
                sample(1900, value=3.0),
            ],
            downsample_overrides={"cpu.usage": 2000},
        )
    )
    assert len(result["series"]) == 1
    assert result["series"][0]["value"] == 6.0
    assert result["series"][0]["count"] == 2


def test_override_combines_with_aggregation_and_quorum():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(500, "b", value=3.0),
                sample(1500, "a", value=10.0),
            ],
            aggregations={"cpu.usage": "max"},
            source_quorum={"cpu.usage": 2},
            downsample_overrides={"cpu.usage": 2000},
        )
    )
    # One 2000ms window; quorum sees the full deduplicated source set.
    assert [row["value"] for row in result["series"]] == [10.0]
    assert result["series"][0]["sources"] == ["a", "b"]


def test_override_combines_with_weights_and_priority():
    result = process(
        payload(
            [
                sample(0, "a", name="w", value=1.0),
                sample(1500, "b", name="w", value=3.0),
                sample(0, "a", name="p", value=2.0),
                sample(1500, "b", name="p", value=8.0),
            ],
            source_weights={"w": {"a": 1, "b": 3}},
            source_priority={"p": ["b", "a"]},
            downsample_overrides={"w": 2000, "p": 2000},
        )
    )
    by_name = {row["name"]: row for row in result["series"]}
    assert by_name["w"]["value"] == 2.5  # (1*1 + 3*3) / (1 + 3)
    assert by_name["w"]["timestamp_ms"] == 0
    assert by_name["p"]["value"] == 8.0  # failover source b only
    assert by_name["p"]["sources"] == ["b"]


def test_gap_fill_uses_each_metrics_own_period():
    metrics = [
        sample(0, name="cpu.usage", value=1.0),
        sample(4000, name="cpu.usage", value=2.0),
        sample(0, name="mem.usage", value=5.0),
        sample(4000, name="mem.usage", value=6.0),
    ]
    result = process(
        payload(
            metrics,
            gap_fill={"cpu.usage": 4000, "mem.usage": 4000},
            downsample_overrides={"cpu.usage": 2000},
        )
    )
    by_name = {}
    for row in result["series"]:
        by_name.setdefault(row["name"], []).append(row)
    # cpu.usage fills on its 2000ms period; mem.usage on the default 1000ms.
    assert [row["timestamp_ms"] for row in by_name["cpu.usage"]] == [0, 2000, 4000]
    assert [row["timestamp_ms"] for row in by_name["mem.usage"]] == [0, 1000, 2000, 3000, 4000]
    fill = by_name["cpu.usage"][1]
    assert fill["value"] == 1.0
    assert fill["count"] == 0
    assert fill["sources"] == []


# -- validation ---------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        ["cpu.usage"],
        "cpu.usage",
        1000,
        {"": 1000},
        {"cpu.usage": True},
        {"cpu.usage": 0},
        {"cpu.usage": -1000},
        {"cpu.usage": 1000.0},
        {"cpu.usage": float("inf")},
        {"cpu.usage": float("nan")},
        {"cpu.usage": "1000"},
        {"cpu.usage": None},
    ],
)
def test_process_invalid_overrides_raise(overrides):
    with pytest.raises(ValueError, match="invalid downsample_override"):
        process(payload([sample(0)], downsample_overrides=overrides))


def test_invalid_override_produces_no_partial_result():
    with pytest.raises(ValueError, match="invalid downsample_override"):
        process(
            payload(
                [sample(0)],
                aggregations={"cpu.usage": "max"},
                downsample_overrides={"cpu.usage": 0},
            )
        )


# -- MetricBatchService.query_series ------------------------------------------


def make_service():
    # A batch's samples must all fall into the window of its
    # max_event_time_ms, so the two downsample_ms windows arrive as two
    # batches.
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [
                sample(900, value=1.0),
                sample(900, name="mem.usage", value=10.0),
            ],
        }
    )
    service.apply_batch(
        {
            "batch_id": "b2",
            "max_event_time_ms": 1900,
            "metrics": [
                sample(1100, value=3.0),
                sample(1100, name="mem.usage", value=30.0),
            ],
        }
    )
    return service


def test_query_series_override_rewindows_from_current_winners():
    service = make_service()
    rows = service.query_series(downsample_overrides={"cpu.usage": 2000})
    by_name = {}
    for row in rows:
        by_name.setdefault(row["name"], []).append(row)
    assert [(row["timestamp_ms"], row["value"]) for row in by_name["cpu.usage"]] == [(0, 2.0)]
    assert [row["timestamp_ms"] for row in by_name["mem.usage"]] == [0, 1000]
    # Without the override the stored windows are unchanged.
    rows = service.query_series()
    assert [row["timestamp_ms"] for row in rows if row["name"] == "cpu.usage"] == [0, 1000]


def test_query_series_override_reflects_late_batches_and_retraction():
    service = make_service()
    # A late batch moves the 1100ms sample's value.
    service.apply_batch(
        {
            "batch_id": "b3",
            "max_event_time_ms": 1900,
            "metrics": [sample(1100, value=9.0)],
        }
    )
    rows = service.query_series(downsample_overrides={"cpu.usage": 2000})
    cpu = [row for row in rows if row["name"] == "cpu.usage"]
    assert [(row["timestamp_ms"], row["value"]) for row in cpu] == [(0, 5.0)]
    # Retracting the correction restores the previous winning sample.
    service.retract_batch("b3")
    rows = service.query_series(downsample_overrides={"cpu.usage": 2000})
    cpu = [row for row in rows if row["name"] == "cpu.usage"]
    assert [(row["timestamp_ms"], row["value"]) for row in cpu] == [(0, 2.0)]
    # Retracting the original batches empties the overridden series too.
    service.retract_batch("b2")
    rows = service.query_series(downsample_overrides={"cpu.usage": 2000})
    cpu = [row for row in rows if row["name"] == "cpu.usage"]
    assert [(row["timestamp_ms"], row["value"]) for row in cpu] == [(0, 1.0)]
    service.retract_batch("b1")
    rows = service.query_series(downsample_overrides={"cpu.usage": 2000})
    assert [row for row in rows if row["name"] == "cpu.usage"] == []


def test_query_series_override_respects_filters_and_gap_fill():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 0, "metrics": [sample(0, value=1.0)]}
    )
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 4000, "metrics": [sample(4000, value=2.0)]}
    )
    rows = service.query_series(
        name="cpu.usage",
        gap_fill={"cpu.usage": 4000},
        downsample_overrides={"cpu.usage": 2000},
    )
    assert [row["timestamp_ms"] for row in rows] == [0, 2000, 4000]
    rows = service.query_series(
        start_ms=1000,
        downsample_overrides={"cpu.usage": 2000},
    )
    # start_ms filters window starts: only the 4000 window remains.
    assert [row["timestamp_ms"] for row in rows] == [4000]


def test_query_series_invalid_overrides_raise():
    service = make_service()
    for overrides in ({"cpu.usage": 0}, {"cpu.usage": True}, {"": 10}, ["x"]):
        with pytest.raises(ValueError, match="invalid downsample_override"):
            service.query_series(downsample_overrides=overrides)
    # A failed query changes nothing: valid queries still work.
    assert len(service.query_series()) == 4


def test_batch_apply_and_retract_ignore_overrides():
    service = MetricBatchService(downsample_ms=1000)
    applied = service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(900)],
            "downsample_overrides": {"cpu.usage": 2000},
        }
    )
    # Batch bookkeeping still follows the constructor downsample_ms.
    assert applied["recomputed_windows"] == 1
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 1900, "metrics": [sample(1100)]}
    )
    assert [row["timestamp_ms"] for row in service.query_series()] == [0, 1000]


# -- CLI ----------------------------------------------------------------------


def test_cli_override_rewindows(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(
            payload(
                [sample(900, value=1.0), sample(1100, value=3.0)],
                downsample_overrides={"cpu.usage": 2000},
            )
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    out = json.loads(completed.stdout)
    assert [(row["timestamp_ms"], row["value"]) for row in out["series"]] == [(0, 2.0)]


def test_cli_invalid_override_exits_2(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(payload([sample(0)], downsample_overrides={"cpu.usage": 0})),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert completed.stderr.strip().endswith("invalid downsample_override")
    assert completed.stdout == ""


# -- HTTP ---------------------------------------------------------------------


@pytest.fixture
def http_service():
    from metric_fusion.server import _make_handler

    service = MetricBatchService(downsample_ms=1000)
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), _make_handler(service, threading.Lock())
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def post(path, body):
        data = json.dumps(body).encode("utf-8")
        req = urllib_request.Request(
            base + path, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib_request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib_error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def get(path):
        with urllib_request.urlopen(base + path) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    yield service, post, get
    server.shutdown()
    server.server_close()
    thread.join()


def test_http_process_accepts_overrides(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/process",
        payload(
            [sample(900, value=1.0), sample(1100, value=3.0)],
            downsample_overrides={"cpu.usage": 2000},
        ),
    )
    assert status == 200
    assert [(row["timestamp_ms"], row["value"]) for row in body["series"]] == [(0, 2.0)]


def test_http_process_invalid_override_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/process",
        payload([sample(0)], downsample_overrides={"cpu.usage": -1}),
    )
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid downsample_override"}


def test_http_query_accepts_overrides(http_service):
    _service, post, _get = http_service
    post(
        "/v1/metric_batches",
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(900, value=1.0)]},
    )
    post(
        "/v1/metric_batches",
        {"batch_id": "b2", "max_event_time_ms": 1900, "metrics": [sample(1100, value=3.0)]},
    )
    status, body = post("/v1/query", {"downsample_overrides": {"cpu.usage": 2000}})
    assert status == 200
    assert [(row["timestamp_ms"], row["value"]) for row in body["series"]] == [(0, 2.0)]


def test_http_query_invalid_override_returns_400_and_keeps_state(http_service):
    service, post, _get = http_service
    post(
        "/v1/metric_batches",
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, value=1.0)]},
    )
    status, body = post("/v1/query", {"downsample_overrides": {"cpu.usage": 1.5}})
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid downsample_override"}
    status, body = post("/v1/query", {"downsample_overrides": ["cpu.usage"]})
    assert status == 400
    assert body["message"] == "invalid downsample_override"
    # State and valid queries still work.
    status, body = post("/v1/query", {"downsample_overrides": {"cpu.usage": 2000}})
    assert status == 200
    assert body["series"][0]["value"] == 1.0
    assert len(service.query_series()) == 1


def test_http_get_endpoints_ignore_overrides(http_service):
    _service, post, get = http_service
    post(
        "/v1/metric_batches",
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(900, value=1.0)]},
    )
    post(
        "/v1/metric_batches",
        {"batch_id": "b2", "max_event_time_ms": 1900, "metrics": [sample(1100, value=3.0)]},
    )
    status, body = get("/v1/series")
    assert status == 200
    # The default query keeps the constructor downsample_ms windows.
    assert [row["timestamp_ms"] for row in body["series"]] == [0, 1000]
    status, body = get("/v1/alerts")
    assert status == 200
    assert body["suppressed_alert_ids"] == []
