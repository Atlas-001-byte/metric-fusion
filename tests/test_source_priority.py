"""Tests for per-metric source-priority failover (source_priority)."""

import json
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from urllib import error as urllib_error
from urllib import request as urllib_request

import pytest

from metric_fusion import BatchError, MetricBatchService, process
from metric_fusion.server import _make_handler


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


PRIORITY = {"cpu.usage": ["a", "b"]}


# -- process(): failover semantics -------------------------------------------


def test_priority_picks_highest_present_source():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(100, "b", value=9.0)],
            source_priority=PRIORITY,
        )
    )
    assert result["series"] == [
        {
            "name": "cpu.usage",
            "labels": {"host": "db-1"},
            "timestamp_ms": 0,
            "value": 1.0,
            "count": 1,
            "sources": ["a"],
        }
    ]


def test_priority_fails_over_to_next_source():
    # Only the second configured source appears: its samples alone form the row.
    result = process(
        payload(
            [sample(0, "b", value=2.0), sample(200, "b", value=4.0)],
            source_priority=PRIORITY,
        )
    )
    assert result["series"][0]["value"] == 3.0
    assert result["series"][0]["count"] == 2
    assert result["series"][0]["sources"] == ["b"]


def test_priority_uses_all_samples_of_winning_source():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "a", value=3.0),
                sample(200, "b", value=100.0),
            ],
            source_priority=PRIORITY,
        )
    )
    row = result["series"][0]
    assert row["value"] == 2.0
    assert row["count"] == 2
    assert row["sources"] == ["a"]


def test_priority_unlisted_source_does_not_participate():
    result = process(
        payload(
            [
                sample(0, "c", value=100.0),
                sample(100, "b", value=4.0),
                sample(200, "b", value=6.0),
            ],
            source_priority=PRIORITY,
        )
    )
    row = result["series"][0]
    assert row["value"] == 5.0
    assert row["count"] == 2
    assert row["sources"] == ["b"]


def test_priority_aggregation_functions():
    metrics = [
        sample(0, "a", value=1.0),
        sample(100, "a", value=3.0),
        sample(200, "a", value=5.0),
    ]
    result = process(
        payload(metrics, aggregations={"cpu.usage": "min"}, source_priority=PRIORITY)
    )
    assert result["series"][0]["value"] == 1.0
    result = process(
        payload(metrics, aggregations={"cpu.usage": "max"}, source_priority=PRIORITY)
    )
    assert result["series"][0]["value"] == 5.0
    result = process(
        payload(metrics, aggregations={"cpu.usage": "sum"}, source_priority=PRIORITY)
    )
    assert result["series"][0]["value"] == 9.0
    result = process(
        payload(
            [sample(0, "b", value=1.0), sample(100, "b", value=3.0)],
            aggregations={"cpu.usage": "last"},
            source_priority=PRIORITY,
        )
    )
    assert result["series"][0]["value"] == 3.0
    # Unconfigured aggregation defaults to avg.
    result = process(payload(metrics, source_priority=PRIORITY))
    assert result["series"][0]["value"] == 3.0


def test_priority_last_uses_greatest_timestamp_of_winning_source():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "b", value=99.0),
                sample(200, "a", value=7.0),
                sample(300, "b", value=100.0),
            ],
            aggregations={"cpu.usage": "last"},
            source_priority=PRIORITY,
        )
    )
    row = result["series"][0]
    # Winner is source a; its last sample is at ts=200.
    assert row["value"] == 7.0
    assert row["sources"] == ["a"]


def test_priority_rounding_and_negative_zero():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(100, "a", value=2.0)],
            source_priority=PRIORITY,
        )
    )
    assert result["series"][0]["value"] == 1.5
    result = process(
        payload([sample(0, "a", value=-0.0)], source_priority=PRIORITY)
    )
    assert result["series"][0]["value"] == 0.0


def test_priority_dedup_before_selection():
    # Identical points collapse with later-wins before source selection.
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(0, "a", value=9.0)],
            source_priority=PRIORITY,
        )
    )
    row = result["series"][0]
    assert row["value"] == 9.0
    assert row["count"] == 1
    assert row["sources"] == ["a"]


def test_priority_dedup_sources_counted_for_winner_count():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(0, "b", value=2.0),
                sample(0, "b", value=3.0),
            ],
            source_priority=PRIORITY,
        )
    )
    row = result["series"][0]
    assert row["value"] == 1.0
    assert row["count"] == 1


def test_priority_per_window_failover():
    # Window 0: only source b present; window 1000: source a is back and wins.
    result = process(
        payload(
            [
                sample(0, "b", value=4.0),
                sample(1000, "a", value=2.0),
                sample(1100, "b", value=99.0),
            ],
            source_priority=PRIORITY,
        )
    )
    assert [(row["timestamp_ms"], row["value"], row["sources"]) for row in result["series"]] == [
        (0, 4.0, ["b"]),
        (1000, 2.0, ["a"]),
    ]


def test_priority_missing_when_no_configured_source_present():
    result = process(
        payload([sample(0, "c", value=9.0)], source_priority=PRIORITY)
    )
    assert result["series"] == [
        {
            "name": "cpu.usage",
            "labels": {"host": "db-1"},
            "timestamp_ms": 0,
            "value": None,
            "count": 0,
            "sources": [],
            "priority_missing": True,
        }
    ]


def test_priority_missing_not_set_on_normal_rows():
    result = process(payload([sample(0, "a")], source_priority=PRIORITY))
    assert "priority_missing" not in result["series"][0]


def test_priority_window_without_any_samples_emits_nothing():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(1000, "a", name="other", value=5.0)],
            source_priority=PRIORITY,
        )
    )
    assert [(row["name"], row["timestamp_ms"]) for row in result["series"]] == [
        ("cpu.usage", 0),
        ("other", 1000),
    ]
    assert "priority_missing" not in result["series"][1]


def test_priority_quorum_uses_full_source_set_before_selection():
    # Quorum 2 is met by {a, b}, then priority picks a alone for the value.
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(100, "b", value=9.0)],
            source_quorum={"cpu.usage": 2},
            source_priority=PRIORITY,
        )
    )
    row = result["series"][0]
    assert row["value"] == 1.0
    assert row["sources"] == ["a"]
    assert row["count"] == 1


def test_priority_quorum_includes_unconfigured_sources():
    # Quorum 2 is met by configured b plus unconfigured c; b wins the row.
    result = process(
        payload(
            [sample(0, "b", value=4.0), sample(100, "c", value=99.0)],
            source_quorum={"cpu.usage": 2},
            source_priority=PRIORITY,
        )
    )
    row = result["series"][0]
    assert row["value"] == 4.0
    assert row["sources"] == ["b"]


def test_priority_quorum_not_met_drops_window_even_if_winner_exists():
    result = process(
        payload(
            [sample(0, "a", value=1.0)],
            source_quorum={"cpu.usage": 2},
            source_priority=PRIORITY,
        )
    )
    assert result["series"] == []


def test_priority_quorum_met_but_no_configured_source_emits_missing_row():
    # Two unconfigured sources meet quorum 2; selection finds no winner.
    result = process(
        payload(
            [sample(0, "c", value=1.0), sample(100, "d", value=2.0)],
            source_quorum={"cpu.usage": 2},
            source_priority=PRIORITY,
        )
    )
    assert result["series"] == [
        {
            "name": "cpu.usage",
            "labels": {"host": "db-1"},
            "timestamp_ms": 0,
            "value": None,
            "count": 0,
            "sources": [],
            "priority_missing": True,
        }
    ]


def test_priority_scoped_by_name():
    result = process(
        payload(
            [
                sample(0, "b", value=9.0),
                sample(0, "b", name="other", value=8.0),
            ],
            source_priority={"cpu.usage": ["a", "b"]},
        )
    )
    rows = {row["name"]: row for row in result["series"]}
    assert rows["cpu.usage"]["value"] == 9.0
    # Unmatched metric keeps the existing plain merge.
    assert rows["other"]["value"] == 8.0
    assert "priority_missing" not in rows["other"]


def test_priority_unmatched_config_leaves_output_unchanged():
    metrics = [sample(0, "a", value=1.0), sample(100, "b", value=2.0)]
    baseline = process(payload(metrics))
    unmatched = process(payload(metrics, source_priority={"other": ["a"]}))
    assert baseline["series"] == unmatched["series"]
    assert set(unmatched) == {"series", "alerts", "suppressed_alert_ids"}


def test_priority_keeps_sorting():
    result = process(
        payload(
            [
                sample(1000, "b", value=2.0),
                sample(0, "b", value=1.0),
                sample(0, "a", name="zzz", value=5.0),
            ],
            source_priority=PRIORITY,
        )
    )
    keys = [(row["name"], row["timestamp_ms"]) for row in result["series"]]
    assert keys == [("cpu.usage", 0), ("cpu.usage", 1000), ("zzz", 0)]


def test_priority_alerts_unaffected():
    alert = {
        "source": "c",
        "name": "cpu.usage",
        "labels": {"host": "db-1"},
        "alert_id": "a1",
        "rule": "cpu-high",
        "timestamp_ms": 0,
        "severity": "warning",
    }
    request = payload([sample(0, "c")], source_priority=PRIORITY)
    request["alerts"] = [alert]
    result = process(request)
    assert result["series"][0]["priority_missing"] is True
    assert result["alerts"] == [
        {"alert_id": "a1", "severity": "warning", "suppressed": False}
    ]
    assert result["suppressed_alert_ids"] == []


# -- validation ---------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "not-a-mapping",
        ["not-a-mapping"],
        {},
        {"": ["a"]},
        {1: ["a"]},
        {"cpu.usage": None},
        {"cpu.usage": "a"},
        {"cpu.usage": {"a": 1}},
        {"cpu.usage": []},
        {"cpu.usage": [""]},
        {"cpu.usage": [1]},
        {"cpu.usage": [None]},
        {"cpu.usage": ["a", "a"]},
        {"cpu.usage": ["a", "", "b"]},
        {"cpu.usage": ["a", "b", "a"]},
    ],
)
def test_invalid_source_priority_in_process(raw):
    with pytest.raises(ValueError, match="^invalid source_priority$"):
        process(payload([sample(0, "a")], source_priority=raw))


def test_source_priority_conflicts_with_source_weights_on_same_target():
    with pytest.raises(ValueError, match="^invalid source_priority$"):
        process(
            payload(
                [sample(0, "a")],
                source_weights={"cpu.usage": {"a": 1.0}},
                source_priority={"cpu.usage": ["a"]},
            )
        )


def test_source_priority_and_weights_coexist_on_different_targets():
    result = process(
        payload(
            [
                sample(0, "a", name="cpu.usage", value=1.0),
                sample(100, "b", name="cpu.usage", value=9.0),
                sample(0, "a", name="mem.usage", value=2.0),
                sample(100, "b", name="mem.usage", value=4.0),
            ],
            source_weights={"mem.usage": {"a": 1.0, "b": 1.0}},
            source_priority={"cpu.usage": ["a", "b"]},
        )
    )
    rows = {row["name"]: row for row in result["series"]}
    assert rows["cpu.usage"]["value"] == 1.0
    assert rows["cpu.usage"]["sources"] == ["a"]
    assert rows["mem.usage"]["value"] == 3.0


def test_invalid_source_priority_is_all_or_nothing():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a")]}
    )
    before = service.query_series()
    with pytest.raises(ValueError, match="^invalid source_priority$"):
        service.query_series(source_priority={"cpu.usage": []})
    with pytest.raises(ValueError, match="^invalid source_priority$"):
        service.query_series(
            source_weights={"cpu.usage": {"a": 1.0}},
            source_priority={"cpu.usage": ["a"]},
        )
    assert service.query_series() == before


# -- CLI ----------------------------------------------------------------------


def test_cli_invalid_source_priority_exits_2(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(payload([sample(0, "a")], source_priority={"cpu.usage": []})),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "invalid source_priority" in completed.stderr


def test_cli_priority_outputs_row(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(
            payload(
                [sample(0, "b", value=6.0)],
                source_priority=PRIORITY,
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
    payload_out = json.loads(completed.stdout)
    assert payload_out["series"][0]["value"] == 6.0
    assert payload_out["series"][0]["sources"] == ["b"]


# -- MetricBatchService -------------------------------------------------------


def test_service_priority_query_and_late_source():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(100, "b", value=4.0)]}
    )
    rows = service.query_series(source_priority=PRIORITY)
    assert [(row["timestamp_ms"], row["value"], row["sources"]) for row in rows] == [
        (0, 4.0, ["b"])
    ]

    # A late batch brings the higher-priority source into the same window; the
    # next query fails over to it.
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900,
         "metrics": [sample(200, "a", value=1.0)]}
    )
    rows = service.query_series(source_priority=PRIORITY)
    assert [(row["timestamp_ms"], row["value"], row["sources"]) for row in rows] == [
        (0, 1.0, ["a"])
    ]


def test_service_priority_value_recomputed_after_retraction():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "b", value=8.0)]}
    )
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900,
         "metrics": [sample(100, "a", value=2.0)]}
    )
    rows = service.query_series(source_priority=PRIORITY)
    assert rows[0]["value"] == 2.0
    assert rows[0]["sources"] == ["a"]

    service.retract_batch("b2")
    rows = service.query_series(source_priority=PRIORITY)
    assert rows[0]["value"] == 8.0
    assert rows[0]["sources"] == ["b"]


def test_service_priority_missing_and_recovery_via_late_batch():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "c", value=7.0)]}
    )
    rows = service.query_series(source_priority=PRIORITY)
    assert rows[0]["value"] is None
    assert rows[0]["priority_missing"] is True
    assert rows[0]["sources"] == []
    assert rows[0]["count"] == 0

    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900,
         "metrics": [sample(100, "b", value=2.0)]}
    )
    rows = service.query_series(source_priority=PRIORITY)
    assert rows[0]["value"] == 2.0
    assert rows[0]["sources"] == ["b"]
    assert "priority_missing" not in rows[0]


def test_service_default_query_ignores_priority():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "a", value=1.0), sample(100, "b", value=3.0)]}
    )
    rows = service.query_series()
    assert rows[0]["value"] == 2.0
    assert set(rows[0]) == {"name", "labels", "timestamp_ms", "value", "count", "sources"}
    assert service.query_alerts()["suppressed_alert_ids"] == []


def test_service_priority_with_filters_and_aggregation():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [
             sample(0, "a", value=1.0),
             sample(100, "b", value=9.0),
         ]}
    )
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 1900,
         "metrics": [sample(1000, "b", value=5.0)]}
    )
    rows = service.query_series(
        aggregations={"cpu.usage": "max"},
        source_priority=PRIORITY,
        start_ms=1000,
    )
    assert [(row["timestamp_ms"], row["value"]) for row in rows] == [(1000, 5.0)]


def test_batch_apply_rejects_source_priority():
    service = MetricBatchService(downsample_ms=1000)
    request = {
        "batch_id": "b1",
        "max_event_time_ms": 900,
        "metrics": [sample(0, "a")],
        "source_priority": PRIORITY,
    }
    with pytest.raises(BatchError) as exc_info:
        service.apply_batch(request)
    assert exc_info.value.status == 400
    assert str(exc_info.value) == "invalid source_priority"
    # The rejected batch never reached the store.
    assert service.query_series() == []
    with pytest.raises(BatchError) as exc_info:
        service.retract_batch("b1")
    assert exc_info.value.status == 404


def test_batch_apply_rejects_invalid_source_priority_shape():
    service = MetricBatchService(downsample_ms=1000)
    request = {
        "batch_id": "b1",
        "max_event_time_ms": 900,
        "metrics": [sample(0, "a")],
        "source_priority": {"cpu.usage": []},
    }
    with pytest.raises(BatchError) as exc_info:
        service.apply_batch(request)
    assert exc_info.value.status == 400
    assert str(exc_info.value) == "invalid source_priority"
    assert service.query_series() == []


def test_retract_does_not_read_source_priority_in_library():
    # The library retract API has no configuration parameter at all.
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a")]}
    )
    result = service.retract_batch("b1")
    assert result["status"] == "retracted"


# -- HTTP ---------------------------------------------------------------------


@pytest.fixture
def http_service():
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


def test_http_query_accepts_source_priority(http_service):
    service, post, _get = http_service
    post(
        "/v1/metric_batches",
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(100, "b", value=6.0)]},
    )
    status, body = post("/v1/query", {"source_priority": PRIORITY})
    assert status == 200
    assert body["series"][0]["value"] == 6.0
    assert body["series"][0]["sources"] == ["b"]


def test_http_query_invalid_source_priority_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post("/v1/query", {"source_priority": {"cpu.usage": []}})
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid source_priority"}


def test_http_query_priority_weights_conflict_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/v1/query",
        {
            "source_priority": {"cpu.usage": ["a"]},
            "source_weights": {"cpu.usage": {"a": 1.0}},
        },
    )
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid source_priority"}


def test_http_batch_apply_rejects_source_priority(http_service):
    service, post, get = http_service
    status, body = post(
        "/v1/metric_batches",
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0, "a")],
            "source_priority": PRIORITY,
        },
    )
    assert status == 400
    assert body["code"] == "metric_batch_invalid"
    assert body["message"] == "invalid source_priority"
    assert service.query_series() == []


def test_http_retract_rejects_source_priority(http_service):
    service, post, get = http_service
    post(
        "/v1/metric_batches",
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a")]},
    )
    status, body = post(
        "/v1/metric_batches/b1/retract", {"source_priority": PRIORITY}
    )
    assert status == 400
    assert body["code"] == "metric_batch_retract_invalid"
    assert body["message"] == "invalid source_priority"
    # The batch is still applied.
    assert len(service.query_series()) == 1


def test_http_get_endpoints_ignore_priority(http_service):
    _service, _post, get = http_service
    _post(
        "/v1/metric_batches",
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0, "a", value=1.0), sample(100, "b", value=9.0)],
        },
    )
    # GET /v1/series never reads query-time source selection.
    status, body = get("/v1/series")
    assert status == 200
    assert body["series"][0]["value"] == 5.0
    assert body["series"][0]["sources"] == ["a", "b"]
    # GET /v1/alerts is unaffected as well.
    status, body = get("/v1/alerts")
    assert status == 200
    assert body["suppressed_alert_ids"] == []

