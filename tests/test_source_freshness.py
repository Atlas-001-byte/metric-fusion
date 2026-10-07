"""Tests for optional per-metric source-freshness (staleness) exclusion."""

import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from metric_fusion import MetricBatchService, process
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


FRESHNESS = {"cpu.usage": 100}


# -- process() ----------------------------------------------------------------


def test_stale_source_is_removed_as_a_whole():
    # a lags the window anchor (b @ 900) by 900 > 100; both of a's samples go.
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(50, "a", value=3.0),
                sample(900, "b", value=10.0),
            ],
            source_lag_tolerance_ms=FRESHNESS,
        )
    )
    assert len(result["series"]) == 1
    row = result["series"][0]
    assert row["value"] == 10.0
    assert row["count"] == 1
    assert row["sources"] == ["b"]


def test_lag_equal_to_tolerance_is_kept():
    # Anchors: a=800, b=900 — the lag is exactly the tolerance.
    kept = process(
        payload(
            [sample(800, "a", value=1.0), sample(900, "b", value=3.0)],
            source_lag_tolerance_ms={"cpu.usage": 100},
        )
    )
    row = kept["series"][0]
    assert row["value"] == 2.0
    assert row["sources"] == ["a", "b"]
    # One millisecond tighter tolerance drops a: the comparison is strict.
    dropped = process(
        payload(
            [sample(800, "a", value=1.0), sample(900, "b", value=3.0)],
            source_lag_tolerance_ms={"cpu.usage": 99},
        )
    )
    row = dropped["series"][0]
    assert row["value"] == 3.0
    assert row["sources"] == ["b"]


def test_source_anchor_is_greatest_deduped_sample_timestamp():
    # a's anchor is its latest sample (850); lag 50 <= 100, so it is kept.
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(850, "a", value=3.0),
                sample(900, "b", value=10.0),
            ],
            source_lag_tolerance_ms=FRESHNESS,
        )
    )
    row = result["series"][0]
    assert row["value"] == pytest.approx((1.0 + 3.0 + 10.0) / 3)
    assert row["sources"] == ["a", "b"]


def test_zero_tolerance_keeps_only_the_freshest_sources():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(900, "b", value=2.0),
                sample(900, "c", value=4.0),
            ],
            source_lag_tolerance_ms={"cpu.usage": 0},
        )
    )
    row = result["series"][0]
    assert row["value"] == 3.0
    assert row["sources"] == ["b", "c"]


def test_filtering_is_independent_per_window():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(900, "b", value=2.0),  # a stale only in window 0
                sample(1000, "a", value=3.0),
                sample(1050, "b", value=5.0),
            ],
            source_lag_tolerance_ms=FRESHNESS,
        )
    )
    assert [row["timestamp_ms"] for row in result["series"]] == [0, 1000]
    assert result["series"][0]["sources"] == ["b"]
    assert result["series"][1]["sources"] == ["a", "b"]


def test_dedup_happens_before_anchor_computation():
    # The later occurrence of the same point wins; the anchor is taken from
    # the deduplicated sample set, so a stays fresh with its 850 reading.
    result = process(
        payload(
            [
                sample(850, "a", value=1.0),
                sample(850, "a", value=9.0),
                sample(900, "b", value=3.0),
            ],
            source_lag_tolerance_ms=FRESHNESS,
        )
    )
    row = result["series"][0]
    assert row["value"] == 6.0
    assert row["sources"] == ["a", "b"]


def test_unmapped_metric_is_untouched():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(900, "b", value=9.0)],
            source_lag_tolerance_ms={"other.metric": 0},
        )
    )
    row = result["series"][0]
    assert row["value"] == 5.0
    assert row["sources"] == ["a", "b"]


def test_absent_none_and_empty_mapping_change_nothing():
    metrics = [sample(0, "a", value=1.0), sample(900, "b", value=9.0)]
    absent = process(payload(metrics))
    none = process(payload(metrics, source_lag_tolerance_ms=None))
    empty = process(payload(metrics, source_lag_tolerance_ms={}))
    assert absent["series"] == none["series"] == empty["series"]
    assert absent["series"][0]["value"] == 5.0


def test_aggregation_runs_on_kept_samples():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "a", value=7.0),
                sample(900, "b", value=10.0),
            ],
            source_lag_tolerance_ms=FRESHNESS,
            aggregations={"cpu.usage": "max"},
        )
    )
    assert result["series"][0]["value"] == 10.0
    assert result["series"][0]["count"] == 1


def test_weighted_merge_uses_only_fresh_sources():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(900, "b", value=10.0),
            ],
            source_lag_tolerance_ms=FRESHNESS,
            source_weights={"cpu.usage": {"a": 1.0, "b": 1.0}},
        )
    )
    row = result["series"][0]
    assert row["value"] == 10.0
    assert row["sources"] == ["b"]


def test_priority_failover_skips_stale_priority_sources():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(850, "b", value=4.0),
                sample(900, "c", value=10.0),
            ],
            source_lag_tolerance_ms=FRESHNESS,
            source_priority={"cpu.usage": ["a", "b"]},
        )
    )
    row = result["series"][0]
    # a is stale; the failover lands on the fresh configured source b.
    assert row["value"] == 4.0
    assert row["sources"] == ["b"]


def test_priority_missing_when_all_priority_sources_stale_but_others_remain():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(900, "b", value=10.0),
            ],
            source_lag_tolerance_ms=FRESHNESS,
            source_priority={"cpu.usage": ["a"]},
        )
    )
    row = result["series"][0]
    assert row["value"] is None
    assert row["count"] == 0
    assert row["sources"] == []
    assert row["priority_missing"] is True


def test_quorum_failing_window_is_emitted_neither_filled_nor_back():
    metrics = [
        sample(0, "a", value=10.0),
        sample(100, "b", value=10.0),
        # Window 1000: a is stale and c (the only remaining partner) leaves b
        # below quorum 2.
        sample(1000, "b", value=2.0),
        sample(1900, "c", value=3.0),
        sample(3000, "a", value=10.0),
        sample(3100, "b", value=10.0),
    ]
    result = process(
        payload(
            metrics,
            source_lag_tolerance_ms=FRESHNESS,
            source_quorum={"cpu.usage": 2},
            gap_fill={"cpu.usage": 5000},
        )
    )
    starts = [row["timestamp_ms"] for row in result["series"]]
    # Window 1000 is quorum-dropped and never resurrected; 2000 plain-fills.
    assert starts == [0, 2000, 3000]


def test_priority_missing_row_requires_quorum_after_staleness():
    # a is the only priority source and is stale; the lone remaining source b
    # fails quorum 2, so no priority_missing row is emitted.
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(900, "b", value=10.0),
            ],
            source_lag_tolerance_ms=FRESHNESS,
            source_priority={"cpu.usage": ["a"]},
            source_quorum={"cpu.usage": 2},
        )
    )
    assert result["series"] == []


def test_freshness_runs_before_outlier_filtering():
    # a's value agrees with the other representatives (no outlier), but its
    # readings are stale; freshness alone removes it.
    result = process(
        payload(
            [
                sample(0, "a", value=2.0),
                sample(900, "b", value=2.0),
                sample(900, "c", value=2.0),
            ],
            source_lag_tolerance_ms=FRESHNESS,
            source_outliers={"cpu.usage": {"min_sources": 2, "tolerance": 0}},
        )
    )
    row = result["series"][0]
    assert row["value"] == 2.0
    assert row["sources"] == ["b", "c"]


def test_rounding_and_negative_zero_normalization_hold():
    result = process(
        payload(
            [
                sample(0, "a", value=-0.0000001),
                sample(900, "b", value=0.0),
            ],
            source_lag_tolerance_ms=FRESHNESS,
        )
    )
    assert result["series"][0]["value"] == 0.0


# -- validation ----------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        ["cpu.usage"],
        "cpu.usage",
        42,
        {"": 100},
        {"cpu.usage": None},
        {"cpu.usage": -1},
        {"cpu.usage": 1.5},
        {"cpu.usage": "100"},
        {"cpu.usage": True},
        {"cpu.usage": False},
        {"cpu.usage": [100]},
        {"cpu.usage": {}},
    ],
)
def test_invalid_source_freshness_in_process(raw):
    with pytest.raises(ValueError, match="^invalid source_freshness$"):
        process(payload([sample(0, "a")], source_lag_tolerance_ms=raw))


def test_zero_tolerance_is_valid():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(900, "b", value=2.0)],
            source_lag_tolerance_ms={"cpu.usage": 0},
        )
    )
    assert result["series"][0]["sources"] == ["b"]


# -- MetricBatchService.query_series -------------------------------------------


def batch_request(batch_id, metrics, max_event_time_ms, **extra):
    request = {
        "batch_id": batch_id,
        "max_event_time_ms": max_event_time_ms,
        "metrics": metrics,
    }
    request.update(extra)
    return request


def test_service_query_filters_stale_sources():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        batch_request(
            "b1",
            [
                sample(0, "a", value=1.0),
                sample(900, "b", value=10.0),
            ],
            900,
        )
    )
    rows = service.query_series(source_lag_tolerance_ms=FRESHNESS)
    assert rows[0]["value"] == 10.0
    assert rows[0]["sources"] == ["b"]
    # A query without the configuration stays unaffected.
    assert service.query_series()[0]["value"] == 5.5
    # Repeating the same query with no new input is consistent.
    again = service.query_series(source_lag_tolerance_ms=FRESHNESS)
    assert again == rows


def test_service_refilter_after_late_correction_and_retraction():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        batch_request(
            "b1",
            [
                sample(0, "a", value=1.0),
                sample(900, "b", value=10.0),
            ],
            900,
        )
    )
    # A later batch refreshes a with an additional winning (higher rank)
    # reading: a's anchor moves to 850 and the whole source group is kept.
    service.apply_batch(batch_request("b2", [sample(850, "a", value=3.0)], 900))
    rows = service.query_series(source_lag_tolerance_ms=FRESHNESS)
    assert rows[0]["sources"] == ["a", "b"]
    assert rows[0]["value"] == pytest.approx((1.0 + 3.0 + 10.0) / 3)
    # Retracting the refresh makes a stale again as a whole.
    service.retract_batch("b2")
    rows = service.query_series(source_lag_tolerance_ms=FRESHNESS)
    assert rows[0]["value"] == 10.0
    assert rows[0]["sources"] == ["b"]


def test_service_invalid_freshness_rejected_without_state_change():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        batch_request("b1", [sample(0, "a"), sample(900, "b")], 900)
    )
    for bad in (["cpu.usage"], {"cpu.usage": -1}, {"cpu.usage": 1.5}, {"": 1}):
        with pytest.raises(ValueError, match="^invalid source_freshness$"):
            service.query_series(source_lag_tolerance_ms=bad)
    assert len(service.query_series()) == 1


def test_service_batch_application_does_not_read_freshness_config():
    service = MetricBatchService(downsample_ms=1000)
    # The key is carried by the batch request but must be ignored.
    service.apply_batch(
        batch_request(
            "b1",
            [sample(0, "a", value=1.0), sample(900, "b", value=9.0)],
            900,
            source_lag_tolerance_ms={"cpu.usage": 0},
        )
    )
    rows = service.query_series()
    assert rows[0]["value"] == 5.0
    assert rows[0]["sources"] == ["a", "b"]


def test_service_late_metrics_do_not_read_freshness_config():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        batch_request("b1", [sample(0, "a", value=1.0)], 900)
    )
    service.submit_late_metrics(
        {"metrics": [sample(900, "b", value=9.0)], "source_lag_tolerance_ms": {"cpu.usage": 0}}
    )
    rows = service.query_series()
    assert rows[0]["sources"] == ["a", "b"]


# -- CLI ------------------------------------------------------------------------


def test_cli_invalid_source_freshness_exits_2(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(payload([sample(0)], source_lag_tolerance_ms={"cpu.usage": -1})),
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "invalid source_freshness" in result.stderr
    assert result.stdout == ""


def test_cli_valid_source_freshness_filters(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(
            payload(
                [sample(0, "a", value=1.0), sample(900, "b", value=10.0)],
                source_lag_tolerance_ms=FRESHNESS,
            )
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    series = json.loads(result.stdout)["series"]
    assert series[0]["value"] == 10.0
    assert series[0]["sources"] == ["b"]


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
        req = urllib.request.Request(
            base + path, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def get(path):
        with urllib.request.urlopen(base + path) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    yield service, post, get
    server.shutdown()
    server.server_close()
    thread.join()


def test_http_query_accepts_source_freshness(http_service):
    _service, post, _get = http_service
    post(
        "/v1/metric_batches",
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [
                sample(0, "a", value=1.0),
                sample(900, "b", value=10.0),
            ],
        },
    )
    status, body = post("/v1/query", {"source_lag_tolerance_ms": FRESHNESS})
    assert status == 200
    assert body["series"][0]["value"] == 10.0
    assert body["series"][0]["sources"] == ["b"]


def test_http_query_invalid_source_freshness_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post("/v1/query", {"source_lag_tolerance_ms": {"cpu.usage": -1}})
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid source_freshness"}


def test_http_process_accepts_source_freshness(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/process",
        payload(
            [sample(0, "a", value=1.0), sample(900, "b", value=10.0)],
            source_lag_tolerance_ms=FRESHNESS,
        ),
    )
    assert status == 200
    assert body["series"][0]["value"] == 10.0
    assert body["series"][0]["sources"] == ["b"]


def test_http_process_invalid_source_freshness_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/process",
        payload(
            [sample(0, "a")],
            source_lag_tolerance_ms={"cpu.usage": True},
        ),
    )
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid source_freshness"}


def test_http_get_endpoints_ignore_source_freshness(http_service):
    _service, post, get = http_service
    post(
        "/v1/metric_batches",
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0, "a", value=1.0), sample(900, "b", value=9.0)],
        },
    )
    # GET /v1/series never reads query-time freshness configuration.
    status, body = get("/v1/series")
    assert status == 200
    assert body["series"][0]["value"] == 5.0
    assert body["series"][0]["sources"] == ["a", "b"]
    status, body = get("/v1/alerts")
    assert status == 200
    assert body["suppressed_alert_ids"] == []
