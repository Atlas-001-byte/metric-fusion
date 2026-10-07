"""Tests for optional per-metric source-outlier filtering of series windows."""

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


OUTLIERS = {"cpu.usage": {"min_sources": 2, "tolerance": 10}}


# -- process() ----------------------------------------------------------------


def test_outlier_source_removed_as_a_whole():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "b", value=2.0),
                sample(200, "c", value=100.0),
                sample(300, "c", value=102.0),
            ],
            source_outliers=OUTLIERS,
        )
    )
    assert len(result["series"]) == 1
    row = result["series"][0]
    assert row["value"] == 1.5
    assert row["count"] == 2
    assert row["sources"] == ["a", "b"]


def test_difference_equal_to_tolerance_is_kept():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "b", value=2.0),
                sample(200, "c", value=12.0),  # diff to median 2.0 is exactly 10
            ],
            source_outliers=OUTLIERS,
        )
    )
    row = result["series"][0]
    assert row["value"] == 5.0
    assert row["sources"] == ["a", "b", "c"]


def test_below_min_sources_everything_is_kept():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(100, "b", value=1000.0)],
            source_outliers={"cpu.usage": {"min_sources": 3, "tolerance": 0}},
        )
    )
    row = result["series"][0]
    assert row["value"] == 500.5
    assert row["sources"] == ["a", "b"]


def test_representative_value_is_source_window_mean():
    # Source a's representative is the mean of its two samples (2.0), so the
    # representatives are 2.0, 2.0, 100.0 and only c is dropped.
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "a", value=3.0),
                sample(200, "b", value=2.0),
                sample(300, "c", value=100.0),
            ],
            source_outliers=OUTLIERS,
        )
    )
    row = result["series"][0]
    assert row["value"] == 2.0
    assert row["count"] == 3
    assert row["sources"] == ["a", "b"]


def test_even_source_count_averages_middle_two_representatives():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "b", value=2.0),
                sample(200, "c", value=3.0),
                sample(300, "d", value=10.0),
            ],
            # Median of [1, 2, 3, 10] is 2.5; b and c differ by exactly 0.5.
            source_outliers={"cpu.usage": {"min_sources": 2, "tolerance": 0.5}},
        )
    )
    row = result["series"][0]
    assert row["value"] == 2.5
    assert row["sources"] == ["b", "c"]


def test_window_emptied_by_filtering_produces_no_row():
    # Median of [1, 2] is 1.5; both representatives differ by 0.5 > 0.
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(100, "b", value=2.0)],
            source_outliers={"cpu.usage": {"min_sources": 2, "tolerance": 0}},
        )
    )
    assert result["series"] == []


def test_unmapped_metrics_are_untouched():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(100, "b", value=1000.0)],
            source_outliers={"other.metric": {"min_sources": 2, "tolerance": 0}},
        )
    )
    row = result["series"][0]
    assert row["value"] == 500.5
    assert row["sources"] == ["a", "b"]


def test_absent_and_none_source_outliers_change_nothing():
    metrics = [sample(0, "a", value=1.0), sample(100, "b", value=1000.0)]
    absent = process(payload(metrics))
    none = process(payload(metrics, source_outliers=None))
    assert absent["series"] == none["series"]
    assert absent["series"][0]["value"] == 500.5


def test_dedup_still_happens_before_filtering():
    # The later occurrence of the same point wins before representatives are
    # computed: c's representative is 2.5, not 100.0, so nothing is filtered.
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "b", value=2.0),
                sample(200, "c", value=100.0),
                sample(200, "c", value=2.5),
            ],
            source_outliers=OUTLIERS,
        )
    )
    row = result["series"][0]
    assert row["value"] == pytest.approx((1.0 + 2.0 + 2.5) / 3)
    assert row["sources"] == ["a", "b", "c"]


def test_quorum_is_judged_on_filtered_coverage():
    metrics = [
        sample(0, "a", value=1.0),
        sample(100, "b", value=2.0),
        sample(200, "c", value=100.0),
    ]
    dropped = process(
        payload(metrics, source_outliers=OUTLIERS, source_quorum={"cpu.usage": 3})
    )
    assert dropped["series"] == []
    kept = process(
        payload(metrics, source_outliers=OUTLIERS, source_quorum={"cpu.usage": 2})
    )
    assert kept["series"][0]["sources"] == ["a", "b"]


def test_quorum_dropped_window_is_not_gap_filled():
    metrics = [
        sample(0, "a", value=10.0),
        sample(100, "b", value=10.0),
        sample(200, "c", value=10.0),
        # Window 1000: c filtered out, remaining 2 sources below quorum 3.
        sample(1000, "a", value=1.0),
        sample(1100, "b", value=2.0),
        sample(1200, "c", value=100.0),
        sample(3000, "a", value=10.0),
        sample(3100, "b", value=10.0),
        sample(3200, "c", value=10.0),
    ]
    result = process(
        payload(
            metrics,
            source_outliers=OUTLIERS,
            source_quorum={"cpu.usage": 3},
            gap_fill={"cpu.usage": 5000},
        )
    )
    starts = [row["timestamp_ms"] for row in result["series"]]
    # 1000 stays dropped (never resurrected); 2000 is a plain gap and fills.
    assert starts == [0, 2000, 3000]
    fill = result["series"][1]
    assert fill["value"] == 10.0
    assert fill["count"] == 0
    assert fill["sources"] == []


def test_gap_fill_runs_after_filtering():
    metrics = [
        sample(0, "a", value=10.0),
        sample(100, "b", value=10.0),
        # Window 1000 empties out entirely under the filter (tolerance 0).
        sample(1000, "x", value=1.0),
        sample(1100, "y", value=2.0),
        sample(3000, "a", value=10.0),
        sample(3100, "b", value=10.0),
    ]
    result = process(
        payload(
            metrics,
            source_outliers={"cpu.usage": {"min_sources": 2, "tolerance": 0}},
            gap_fill={"cpu.usage": 5000},
        )
    )
    starts = [row["timestamp_ms"] for row in result["series"]]
    assert starts == [0, 1000, 2000, 3000]
    for filled in result["series"][1:3]:
        assert filled["value"] == 10.0
        assert filled["count"] == 0
        assert filled["sources"] == []


def test_weighted_merge_uses_filtered_sources():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "b", value=2.0),
                sample(200, "c", value=100.0),
            ],
            source_outliers=OUTLIERS,
            source_weights={"cpu.usage": {"a": 1.0, "b": 1.0, "c": 100.0}},
        )
    )
    row = result["series"][0]
    assert row["value"] == 1.5
    assert row["sources"] == ["a", "b"]


def test_priority_failover_uses_filtered_sources():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "b", value=2.0),
                sample(200, "c", value=100.0),
            ],
            source_outliers=OUTLIERS,
            source_priority={"cpu.usage": ["c", "a"]},
        )
    )
    row = result["series"][0]
    # c is filtered out, so the failover lands on a.
    assert row["value"] == 1.0
    assert row["sources"] == ["a"]


def test_filter_applies_per_window():
    metrics = [
        sample(0, "a", value=1.0),
        sample(100, "b", value=2.0),
        sample(200, "c", value=100.0),  # c is an outlier only in window 0
        sample(1000, "a", value=50.0),
        sample(1100, "b", value=52.0),
        sample(1200, "c", value=54.0),
    ]
    result = process(payload(metrics, source_outliers=OUTLIERS))
    assert [row["timestamp_ms"] for row in result["series"]] == [0, 1000]
    assert result["series"][0]["sources"] == ["a", "b"]
    assert result["series"][1]["sources"] == ["a", "b", "c"]


def test_aggregation_runs_on_filtered_samples():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "b", value=3.0),
                sample(200, "c", value=100.0),
            ],
            source_outliers=OUTLIERS,
            aggregations={"cpu.usage": "max"},
        )
    )
    assert result["series"][0]["value"] == 3.0


# -- validation ----------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        ["cpu.usage"],
        {"cpu.usage": None},
        {"cpu.usage": [2, 10]},
        {"": {"min_sources": 2, "tolerance": 1}},
        {"cpu.usage": {"min_sources": 2}},
        {"cpu.usage": {"tolerance": 1}},
        {"cpu.usage": {"min_sources": 2, "tolerance": 1, "extra": 1}},
        {"cpu.usage": {"min_sources": True, "tolerance": 1}},
        {"cpu.usage": {"min_sources": 1, "tolerance": 1}},
        {"cpu.usage": {"min_sources": 0, "tolerance": 1}},
        {"cpu.usage": {"min_sources": 2.0, "tolerance": 1}},
        {"cpu.usage": {"min_sources": "2", "tolerance": 1}},
        {"cpu.usage": {"min_sources": 2, "tolerance": -1}},
        {"cpu.usage": {"min_sources": 2, "tolerance": True}},
        {"cpu.usage": {"min_sources": 2, "tolerance": "1"}},
        {"cpu.usage": {"min_sources": 2, "tolerance": float("nan")}},
        {"cpu.usage": {"min_sources": 2, "tolerance": float("inf")}},
    ],
)
def test_invalid_source_outliers_in_process(raw):
    with pytest.raises(ValueError, match="invalid source_outliers"):
        process(payload([sample(0, "a")], source_outliers=raw))


def test_valid_source_outliers_accepted_forms():
    # Zero tolerance and integer-typed tolerance are fine.
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(100, "b", value=1.0)],
            source_outliers={"cpu.usage": {"min_sources": 2, "tolerance": 0}},
        )
    )
    assert result["series"][0]["value"] == 1.0


# -- MetricBatchService.query_series -------------------------------------------


def batch_request(batch_id, metrics, max_event_time_ms, **extra):
    request = {
        "batch_id": batch_id,
        "max_event_time_ms": max_event_time_ms,
        "metrics": metrics,
    }
    request.update(extra)
    return request


def test_service_query_filters_outliers():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        batch_request(
            "b1",
            [
                sample(0, "a", value=1.0),
                sample(100, "b", value=2.0),
                sample(200, "c", value=100.0),
            ],
            900,
        )
    )
    rows = service.query_series(source_outliers=OUTLIERS)
    assert rows[0]["value"] == 1.5
    assert rows[0]["sources"] == ["a", "b"]
    # A query without the configuration is unaffected.
    assert service.query_series()[0]["value"] == pytest.approx(103.0 / 3)


def test_service_refilter_after_late_correction_and_retraction():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        batch_request(
            "b1",
            [
                sample(0, "a", value=1.0),
                sample(100, "b", value=2.0),
                sample(200, "c", value=100.0),
            ],
            900,
        )
    )
    # Late correction: c's reading was really 2.5 — no outlier anymore.
    service.apply_batch(batch_request("b2", [sample(200, "c", value=2.5)], 900))
    rows = service.query_series(source_outliers=OUTLIERS)
    assert rows[0]["value"] == pytest.approx((1.0 + 2.0 + 2.5) / 3)
    assert rows[0]["sources"] == ["a", "b", "c"]
    # Retracting the correction restores the outlier and the filtering.
    service.retract_batch("b2")
    rows = service.query_series(source_outliers=OUTLIERS)
    assert rows[0]["value"] == 1.5
    assert rows[0]["sources"] == ["a", "b"]


def test_service_batch_order_does_not_change_filtering():
    def build(order):
        service = MetricBatchService(downsample_ms=1000)
        batches = {
            "b1": batch_request("b1", [sample(0, "a", value=1.0)], 900),
            "b2": batch_request("b2", [sample(100, "b", value=2.0)], 900),
            "b3": batch_request("b3", [sample(200, "c", value=100.0)], 900),
        }
        for batch_id in order:
            service.apply_batch(batches[batch_id])
        return service.query_series(source_outliers=OUTLIERS)

    assert build(["b1", "b2", "b3"]) == build(["b3", "b2", "b1"])


def test_service_invalid_source_outliers_rejected():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(batch_request("b1", [sample(0, "a")], 900))
    for bad in (
        ["cpu.usage"],
        {"cpu.usage": {"min_sources": 1, "tolerance": 0}},
        {"cpu.usage": {"min_sources": 2}},
        {"cpu.usage": {"min_sources": 2, "tolerance": -0.5}},
    ):
        with pytest.raises(ValueError, match="invalid source_outliers"):
            service.query_series(source_outliers=bad)
    # A failed query changes nothing: the service still answers normally.
    assert len(service.query_series()) == 1


def test_service_quorum_and_gap_fill_after_filtering():
    service = MetricBatchService(downsample_ms=1000)
    # One batch per window: a batch's samples must lie in its own window.
    service.apply_batch(
        batch_request(
            "b1",
            [
                sample(0, "a", value=10.0),
                sample(100, "b", value=10.0),
                sample(200, "c", value=10.0),
            ],
            900,
        )
    )
    # Window 1000: c is filtered out, the remaining 2 sources miss quorum 3.
    service.apply_batch(
        batch_request(
            "b2",
            [
                sample(1000, "a", value=1.0),
                sample(1100, "b", value=2.0),
                sample(1200, "c", value=100.0),
            ],
            1900,
        )
    )
    service.apply_batch(
        batch_request(
            "b3",
            [
                sample(3000, "a", value=10.0),
                sample(3100, "b", value=10.0),
                sample(3200, "c", value=10.0),
            ],
            3900,
        )
    )
    rows = service.query_series(
        source_outliers=OUTLIERS,
        source_quorum={"cpu.usage": 3},
        gap_fill={"cpu.usage": 5000},
    )
    assert [row["timestamp_ms"] for row in rows] == [0, 2000, 3000]


# -- CLI ------------------------------------------------------------------------


def test_cli_invalid_source_outliers_exits_2(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(payload([sample(0)], source_outliers={"cpu.usage": {"min_sources": 1, "tolerance": 0}})),
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "invalid source_outliers" in result.stderr
    assert result.stdout == ""


def test_cli_valid_source_outliers_filters(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(
            payload(
                [
                    sample(0, "a", value=1.0),
                    sample(100, "b", value=2.0),
                    sample(200, "c", value=100.0),
                ],
                source_outliers=OUTLIERS,
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
    assert series[0]["value"] == 1.5
    assert series[0]["sources"] == ["a", "b"]


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


def test_http_query_accepts_source_outliers(http_service):
    _service, post, _get = http_service
    post(
        "/v1/metric_batches",
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [
                sample(0, "a", value=1.0),
                sample(100, "b", value=2.0),
                sample(200, "c", value=100.0),
            ],
        },
    )
    status, body = post("/v1/query", {"source_outliers": OUTLIERS})
    assert status == 200
    assert body["series"][0]["value"] == 1.5
    assert body["series"][0]["sources"] == ["a", "b"]


def test_http_query_invalid_source_outliers_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/v1/query", {"source_outliers": {"cpu.usage": {"min_sources": 2}}}
    )
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid source_outliers"}


def test_http_process_accepts_source_outliers(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/process",
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "b", value=2.0),
                sample(200, "c", value=100.0),
            ],
            source_outliers=OUTLIERS,
        ),
    )
    assert status == 200
    assert body["series"][0]["value"] == 1.5
    assert body["series"][0]["sources"] == ["a", "b"]


def test_http_process_invalid_source_outliers_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/process",
        payload(
            [sample(0, "a")],
            source_outliers={"cpu.usage": {"min_sources": 2, "tolerance": -1}},
        ),
    )
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid source_outliers"}


def test_http_get_endpoints_ignore_source_outliers(http_service):
    _service, post, get = http_service
    post(
        "/v1/metric_batches",
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0, "a", value=1.0), sample(100, "b", value=9.0)],
        },
    )
    # GET /v1/series never reads query-time outlier filtering.
    status, body = get("/v1/series")
    assert status == 200
    assert body["series"][0]["value"] == 5.0
    assert body["series"][0]["sources"] == ["a", "b"]
    # GET /v1/alerts is unaffected as well.
    status, body = get("/v1/alerts")
    assert status == 200
    assert body["suppressed_alert_ids"] == []
