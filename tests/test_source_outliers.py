"""Tests for per-metric source outlier filtering (source_outliers)."""

import json
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from urllib import error as urllib_error
from urllib import request as urllib_request

import pytest

from metric_fusion import MetricBatchService, process


def sample(ts, source="a", value=1.0, name="cpu.usage", labels=None):
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


POLICY = {"cpu.usage": {"min_sources": 3, "tolerance": 1.0}}


# -- process(): filtering semantics -------------------------------------------


def test_single_outlier_source_group_is_removed():
    result = process(
        payload(
            [sample(0, "a", 1.0), sample(0, "b", 2.0), sample(0, "c", 100.0)],
            source_outliers=POLICY,
        )
    )
    assert result["series"] == [
        {
            "name": "cpu.usage",
            "labels": {"host": "db-1"},
            "timestamp_ms": 0,
            "value": 1.5,
            "count": 2,
            "sources": ["a", "b"],
        }
    ]


def test_equality_with_tolerance_is_kept_not_filtered():
    # Representatives 1.0/2.0/3.0: median 2.0; the differences are exactly 1.0
    # which is not strictly greater than tolerance, so every source survives.
    result = process(
        payload(
            [sample(0, "a", 1.0), sample(0, "b", 2.0), sample(0, "c", 3.0)],
            source_outliers=POLICY,
        )
    )
    assert result["series"][0]["sources"] == ["a", "b", "c"]
    assert result["series"][0]["count"] == 3


def test_fewer_sources_than_min_keeps_everything():
    result = process(
        payload(
            [sample(0, "a", 1.0), sample(0, "b", 100.0)],
            source_outliers={"cpu.usage": {"min_sources": 3, "tolerance": 0.0}},
        )
    )
    assert result["series"][0]["sources"] == ["a", "b"]
    assert result["series"][0]["value"] == 50.5


def test_source_representative_is_mean_of_its_window_values():
    # Source a has values 1.0 and 3.0 -> representative 2.0; b=2.0, c=100.0.
    # Median of (2.0, 2.0, 100.0) is 2.0, so c is dropped and a keeps both
    # samples (count 3 from a and b together).
    result = process(
        payload(
            [
                sample(0, "a", 1.0),
                sample(100, "a", 3.0),
                sample(0, "b", 2.0),
                sample(0, "c", 100.0),
            ],
            source_outliers=POLICY,
        )
    )
    row = result["series"][0]
    assert row["value"] == 2.0
    assert row["count"] == 3
    assert row["sources"] == ["a", "b"]


def test_even_source_count_averages_middle_pair_for_median():
    # Representatives 1,2,3,100 -> median 2.5; tolerance 0.5 keeps 2 and 3.
    result = process(
        payload(
            [
                sample(0, "a", 1.0),
                sample(0, "b", 2.0),
                sample(0, "c", 3.0),
                sample(0, "d", 100.0),
            ],
            source_outliers={"cpu.usage": {"min_sources": 4, "tolerance": 0.5}},
        )
    )
    row = result["series"][0]
    assert row["sources"] == ["b", "c"]
    assert row["value"] == 2.5


def test_filtering_is_independent_per_window():
    # Window 0: all three agree, window 1000: c is an outlier.
    result = process(
        payload(
            [
                sample(0, "a", 1.0),
                sample(0, "b", 2.0),
                sample(0, "c", 3.0),
                sample(1000, "a", 1.0),
                sample(1000, "b", 2.0),
                sample(1000, "c", 100.0),
            ],
            source_outliers=POLICY,
        )
    )
    rows = result["series"]
    assert [row["sources"] for row in rows] == [["a", "b", "c"], ["a", "b"]]


def test_filtering_scoped_by_name_and_labels():
    result = process(
        payload(
            [
                sample(0, "a", name="x", value=1.0),
                sample(0, "b", name="x", value=2.0),
                sample(0, "c", name="x", value=100.0),
                sample(0, "a", value=1.0),
                sample(0, "b", value=100.0),
            ],
            source_outliers={"x": {"min_sources": 3, "tolerance": 1.0}},
        )
    )
    rows_by_key = {(row["name"], row["labels"]["host"]): row for row in result["series"]}
    # The configured metric x loses source c; the unmatched metric keeps both.
    assert rows_by_key[("x", "db-1")]["sources"] == ["a", "b"]
    assert rows_by_key[("cpu.usage", "db-1")]["sources"] == ["a", "b"]
    assert rows_by_key[("cpu.usage", "db-1")]["value"] == 50.5
    assert len(rows_by_key) == 2


def test_absent_none_or_unmatched_config_leaves_output_unchanged():
    metrics = [sample(0, "a", 1.0), sample(0, "b", 2.0), sample(0, "c", 100.0)]
    baseline = process(payload(metrics))
    as_none = process(payload(metrics, source_outliers=None))
    unmatched = process(
        payload(metrics, source_outliers={"other": {"min_sources": 2, "tolerance": 0}})
    )
    assert baseline["series"] == as_none["series"] == unmatched["series"]
    assert set(as_none) == {"series", "alerts", "suppressed_alert_ids"}


def test_dedup_happens_before_outlier_filtering():
    # The duplicate c point collapses (later wins) before representatives are
    # computed, so sources a/b/c each contribute one winning value and agree.
    result = process(
        payload(
            [
                sample(0, "c", 100.0),
                sample(0, "c", 2.0),
                sample(0, "a", 2.0),
                sample(0, "b", 2.0),
            ],
            source_outliers=POLICY,
        )
    )
    row = result["series"][0]
    assert row["sources"] == ["a", "b", "c"]
    assert row["count"] == 3
    assert row["value"] == 2.0


# -- ordering relative to the other window options ----------------------------


def test_quorum_is_judged_after_filtering():
    # Three sources are present but the outlier is removed, leaving two; the
    # quorum-3 window must be dropped entirely.
    result = process(
        payload(
            [sample(0, "a", 1.0), sample(0, "b", 2.0), sample(0, "c", 100.0)],
            source_outliers=POLICY,
            source_quorum={"cpu.usage": 3},
        )
    )
    assert result["series"] == []


def test_quorum_passes_on_retained_sources():
    result = process(
        payload(
            [sample(0, "a", 1.0), sample(0, "b", 2.0), sample(0, "c", 100.0)],
            source_outliers=POLICY,
            source_quorum={"cpu.usage": 2},
        )
    )
    assert result["series"][0]["sources"] == ["a", "b"]


def test_aggregation_runs_over_surviving_samples_only():
    result = process(
        payload(
            [sample(0, "a", 1.0), sample(0, "b", 2.0), sample(0, "c", 100.0)],
            source_outliers=POLICY,
            aggregations={"cpu.usage": "max"},
        )
    )
    assert result["series"][0]["value"] == 2.0


def test_source_weights_apply_after_filtering():
    result = process(
        payload(
            [sample(0, "a", 1.0), sample(0, "b", 2.0), sample(0, "c", 100.0)],
            source_outliers=POLICY,
            source_weights={"cpu.usage": {"a": 2.0, "b": 1.0, "c": 1.0}},
        )
    )
    row = result["series"][0]
    assert row["value"] == round(4.0 / 3.0, 6)
    assert row["sources"] == ["a", "b"]
    assert row["count"] == 2


def test_source_priority_chooses_among_survivors():
    # c would win by priority but it is filtered out; the next configured
    # surviving source (a) provides the row.
    result = process(
        payload(
            [sample(0, "a", 2.0), sample(0, "b", 3.0), sample(0, "c", 100.0)],
            source_outliers=POLICY,
            source_priority={"cpu.usage": ["c", "a", "b"]},
        )
    )
    row = result["series"][0]
    assert row["sources"] == ["a"]
    assert row["value"] == 2.0


def test_dropped_window_is_not_resurrected_by_gap_fill():
    metrics = [
        sample(0, "a", 1.0), sample(0, "b", 2.0), sample(0, "c", 3.0),
        sample(1000, "a", 1.0), sample(1000, "b", 2.0), sample(1000, "c", 100.0),
        sample(2000, "a", 1.0), sample(2000, "b", 2.0), sample(2000, "c", 3.0),
    ]
    # Window 1000 keeps a/b so it is emitted; instead force that window below
    # coverage by pairing the filter with quorum 3.
    result = process(
        payload(
            metrics,
            source_outliers=POLICY,
            source_quorum={"cpu.usage": 3},
            gap_fill={"cpu.usage": 100000},
        )
    )
    assert [row["timestamp_ms"] for row in result["series"]] == [0, 2000]


def test_alerts_are_unaffected_by_outlier_filtering():
    alert = {
        "source": "c",
        "name": "cpu.usage",
        "labels": {"host": "db-1"},
        "alert_id": "a1",
        "rule": "cpu-high",
        "timestamp_ms": 0,
        "severity": "warning",
    }
    request = payload(
        [sample(0, "a", 1.0), sample(0, "b", 2.0), sample(0, "c", 100.0)],
        source_outliers=POLICY,
    )
    request["alerts"] = [alert]
    result = process(request)
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
        {"cpu.usage": None},
        {"cpu.usage": "x"},
        {"cpu.usage": []},
        {"": {"min_sources": 2, "tolerance": 0}},
        {1: {"min_sources": 2, "tolerance": 0}},
        {"cpu.usage": {"min_sources": 1, "tolerance": 0}},
        {"cpu.usage": {"min_sources": 0, "tolerance": 0}},
        {"cpu.usage": {"min_sources": -2, "tolerance": 0}},
        {"cpu.usage": {"min_sources": 2.0, "tolerance": 0}},
        {"cpu.usage": {"min_sources": True, "tolerance": 0}},
        {"cpu.usage": {"min_sources": False, "tolerance": 0}},
        {"cpu.usage": {"min_sources": "2", "tolerance": 0}},
        {"cpu.usage": {"min_sources": 2, "tolerance": -0.1}},
        {"cpu.usage": {"min_sources": 2, "tolerance": -1}},
        {"cpu.usage": {"min_sources": 2, "tolerance": float("inf")}},
        {"cpu.usage": {"min_sources": 2, "tolerance": float("nan")}},
        {"cpu.usage": {"min_sources": 2, "tolerance": "0"}},
        {"cpu.usage": {"min_sources": 2, "tolerance": True}},
        {"cpu.usage": {"min_sources": 2, "tolerance": False}},
        {"cpu.usage": {"min_sources": 2, "tolerance": 0, "extra": 1}},
        {"cpu.usage": {"tolerance": 0}},
        {"cpu.usage": {"min_sources": 2}},
    ],
)
def test_invalid_source_outliers_in_process(raw):
    with pytest.raises(ValueError, match="^invalid source_outliers$"):
        process(payload([sample(0, "a")], source_outliers=raw))


def test_empty_mapping_is_valid_and_inert():
    result = process(
        payload(
            [sample(0, "a", 1.0), sample(0, "b", 100.0)],
            source_outliers={},
        )
    )
    assert result["series"][0]["value"] == 50.5


def test_invalid_source_outliers_is_all_or_nothing():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a")]}
    )
    before = service.query_series()
    with pytest.raises(ValueError, match="^invalid source_outliers$"):
        service.query_series(source_outliers={"cpu.usage": {"min_sources": 1, "tolerance": 0}})
    assert service.query_series() == before


# -- CLI ----------------------------------------------------------------------


def test_cli_invalid_source_outliers_exits_2(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(
            payload(
                [sample(0, "a")],
                source_outliers={"cpu.usage": {"min_sources": 1, "tolerance": 0}},
            )
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "invalid source_outliers" in completed.stderr


def test_cli_filters_outlier(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(
            payload(
                [sample(0, "a", 1.0), sample(0, "b", 2.0), sample(0, "c", 100.0)],
                source_outliers=POLICY,
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
    body = json.loads(completed.stdout)
    assert body["series"][0]["sources"] == ["a", "b"]
    assert body["series"][0]["value"] == 1.5


# -- MetricBatchService -------------------------------------------------------


def test_service_query_filters_and_validates():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [
                sample(100, "a", 1.0),
                sample(200, "b", 2.0),
                sample(300, "c", 100.0),
            ],
        }
    )
    rows = service.query_series(source_outliers=POLICY)
    assert rows[0]["sources"] == ["a", "b"]
    assert rows[0]["value"] == 1.5

    for raw in (
        "x",
        {"x": {"min_sources": 1, "tolerance": 0}},
        {"x": {"min_sources": 2, "tolerance": -1}},
        {"x": {"min_sources": True, "tolerance": 0}},
        {"x": {"min_sources": 2, "tolerance": 0, "extra": 1}},
        {"": {"min_sources": 2, "tolerance": 0}},
    ):
        with pytest.raises(ValueError, match="^invalid source_outliers$"):
            service.query_series(source_outliers=raw)


def test_service_default_query_ignores_outliers():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [
                sample(0, "a", 1.0),
                sample(100, "b", 2.0),
                sample(200, "c", 100.0),
            ],
        }
    )
    rows = service.query_series()
    assert rows[0]["value"] == round(103.0 / 3.0, 6)
    assert set(rows[0]) == {"name", "labels", "timestamp_ms", "value", "count", "sources"}
    assert service.query_alerts()["suppressed_alert_ids"] == []


def test_service_refilters_after_late_correction_and_retraction():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0, "a", 10.0), sample(100, "b", 100.0)],
        }
    )
    # Only two sources: below min_sources, both retained.
    rows = service.query_series(source_outliers=POLICY)
    assert rows[0]["sources"] == ["a", "b"]

    # A late batch adds an agreeing third source: now the median is 10.0 and
    # the isolated source b (100.0) is filtered out.
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900, "metrics": [sample(200, "c", 10.0)]}
    )
    rows = service.query_series(source_outliers=POLICY)
    assert rows[0]["sources"] == ["a", "c"]
    assert rows[0]["value"] == 10.0

    # Retracting the correction drops coverage back below min_sources: b is
    # retained again and the window recomputes from the surviving winners.
    service.retract_batch("b2")
    rows = service.query_series(source_outliers=POLICY)
    assert rows[0]["sources"] == ["a", "b"]
    assert rows[0]["value"] == 55.0


def test_service_refilters_after_winning_patch():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [
                sample(0, "a", 1.0),
                sample(0, "b", 2.0),
                sample(0, "c", 100.0),
            ],
        }
    )
    assert service.query_series(source_outliers=POLICY)[0]["sources"] == ["a", "b"]

    # A higher-rank batch (same window, later batch_id) corrects c's point
    # into agreement: c rejoins.
    service.apply_batch(
        {
            "batch_id": "b2",
            "max_event_time_ms": 900,
            "metrics": [sample(0, "c", 3.0)],
        }
    )
    rows = service.query_series(source_outliers=POLICY)
    assert rows[0]["sources"] == ["a", "b", "c"]
    assert rows[0]["value"] == 2.0


def test_batch_apply_does_not_require_or_persist_config():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [
                sample(0, "a", 1.0),
                sample(0, "b", 2.0),
                sample(0, "c", 100.0),
            ],
            "source_outliers": POLICY,
        }
    )
    # The batch request may carry the key but it is not persisted: the plain
    # stored window still contains all three sources.
    rows = service.query_series()
    assert rows[0]["sources"] == ["a", "b", "c"]
    assert rows[0]["value"] == round(103.0 / 3.0, 6)


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


def _three_source_batch():
    return {
        "batch_id": "b1",
        "max_event_time_ms": 900,
        "metrics": [
            sample(0, "a", 1.0),
            sample(100, "b", 2.0),
            sample(200, "c", 100.0),
        ],
    }


def test_http_query_accepts_source_outliers(http_service):
    _service, post, _get = http_service
    post("/v1/metric_batches", _three_source_batch())
    status, body = post("/v1/query", {"source_outliers": POLICY})
    assert status == 200
    assert body["series"][0]["sources"] == ["a", "b"]
    assert body["series"][0]["value"] == 1.5


def test_http_query_invalid_source_outliers_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/v1/query", {"source_outliers": {"cpu.usage": {"min_sources": 1, "tolerance": 0}}}
    )
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid source_outliers"}


def test_http_process_accepts_source_outliers(http_service):
    _service, post, _get = http_service
    request = payload(
        [sample(0, "a", 1.0), sample(0, "b", 2.0), sample(0, "c", 100.0)],
        source_outliers=POLICY,
    )
    status, body = post("/process", request)
    assert status == 200
    assert body["series"][0]["sources"] == ["a", "b"]


def test_http_process_invalid_source_outliers_returns_400(http_service):
    _service, post, _get = http_service
    request = payload(
        [sample(0, "a")],
        source_outliers={"cpu.usage": {"min_sources": 2, "tolerance": -1}},
    )
    status, body = post("/process", request)
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid source_outliers"}


def test_http_get_endpoints_ignore_source_outliers(http_service):
    _service, post, get = http_service
    post("/v1/metric_batches", _three_source_batch())
    # GET endpoints accept no configuration and keep the unfiltered window.
    status, body = get("/v1/series")
    assert status == 200
    assert body["series"][0]["sources"] == ["a", "b", "c"]
    status, body = get("/v1/alerts")
    assert status == 200
    assert body["suppressed_alert_ids"] == []
