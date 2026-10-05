"""Tests for distributional window aggregations: median, p95, p99."""

import json
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from urllib import error as urllib_error
from urllib import request as urllib_request

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


def window_value(metrics, func, **extra):
    result = process(payload(metrics, aggregations={"cpu.usage": func}, **extra))
    assert len(result["series"]) == 1
    return result["series"][0]


# -- median -------------------------------------------------------------------


def test_median_odd_count():
    metrics = [sample(i, value=v) for i, v in enumerate([3.0, 1.0, 2.0])]
    assert window_value(metrics, "median")["value"] == 2.0


def test_median_even_count_averages_middle_pair():
    metrics = [sample(i, value=v) for i, v in enumerate([4.0, 1.0, 3.0, 2.0])]
    row = window_value(metrics, "median")
    assert row["value"] == 2.5  # middle pair of [1,2,3,4]
    assert row["count"] == 4
    assert row["sources"] == ["a"]


def test_median_single_sample():
    assert window_value([sample(0, value=7.0)], "median")["value"] == 7.0


def test_median_two_samples_is_their_mean():
    metrics = [sample(0, value=2.0), sample(100, value=4.0)]
    assert window_value(metrics, "median")["value"] == 3.0


# -- nearest-rank percentiles -------------------------------------------------


def test_p95_uses_ceil_rank_without_interpolation():
    # n=20: rank ceil(0.95*20)=19 -> 19th sorted value, no interpolation.
    values = list(range(1, 21))  # 1..20
    metrics = [sample(i, value=float(v)) for i, v in enumerate(values)]
    row = window_value(metrics, "p95")
    assert row["value"] == 19.0
    assert row["count"] == 20


def test_p99_uses_ceil_rank_without_interpolation():
    # n=20: rank ceil(0.99*20)=20 -> maximum.
    values = list(range(1, 21))
    metrics = [sample(i, value=float(v)) for i, v in enumerate(values)]
    assert window_value(metrics, "p99")["value"] == 20.0


def test_percentile_rank_for_n_40():
    # n=40: p95 rank 38, p99 rank 40.
    values = list(range(1, 41))
    metrics = [sample(i, value=float(v)) for i, v in enumerate(values)]
    assert window_value(metrics, "p95")["value"] == 38.0
    assert window_value(metrics, "p99")["value"] == 40.0


def test_percentiles_of_single_sample_equal_it():
    assert window_value([sample(0, value=5.0)], "p95")["value"] == 5.0
    assert window_value([sample(0, value=5.0)], "p99")["value"] == 5.0


def test_percentile_picks_value_not_interpolated_position():
    # n=5: both ranks are 5, so both percentiles equal the maximum rather
    # than an interpolated point short of it.
    values = [1.0, 2.0, 3.0, 4.0, 100.0]
    metrics = [sample(i, value=v) for i, v in enumerate(values)]
    assert window_value(metrics, "p95")["value"] == 100.0
    assert window_value(metrics, "p99")["value"] == 100.0


# -- ordering, dedup and invariants ------------------------------------------


def test_distribution_functions_independent_of_arrival_order():
    values = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0,
              11.0, 21.0, 31.0, 41.0, 51.0, 61.0, 71.0, 81.0, 91.0, 101.0]
    ascending = [sample(i, value=v) for i, v in enumerate(sorted(values))]
    descending = [sample(i, value=v) for i, v in enumerate(sorted(values, reverse=True))]
    for func in ("median", "p95", "p99"):
        first = window_value(ascending, func)
        second = window_value(descending, func)
        assert first["value"] == second["value"]
    assert window_value(ascending, "median")["value"] == 55.5
    assert window_value(ascending, "p95")["value"] == 100.0
    assert window_value(ascending, "p99")["value"] == 101.0


def test_distribution_functions_use_deduplicated_samples():
    # Identical point (same source/name/labels/timestamp) collapses with
    # later-wins; the window then holds a single sample.
    metrics = [sample(0, value=1.0), sample(0, value=9.0)]
    row = window_value(metrics, "median")
    assert row == {
        "name": "cpu.usage",
        "labels": {"host": "db-1"},
        "timestamp_ms": 0,
        "value": 9.0,
        "count": 1,
        "sources": ["a"],
    }
    assert window_value(metrics, "p99")["value"] == 9.0


def test_distribution_row_shape_is_unchanged():
    row = window_value([sample(0, value=1.0), sample(100, value=2.0)], "p95")
    assert set(row) == {"name", "labels", "timestamp_ms", "value", "count", "sources"}


def test_distribution_rounding_and_negative_zero():
    metrics = [sample(0, value=1.0 / 3.0), sample(100, value=2.0 / 3.0)]
    row = window_value(metrics, "median")
    assert row["value"] == 0.5
    neg = window_value([sample(0, value=-0.0)], "median")
    assert neg["value"] == 0.0
    assert str(neg["value"]) != "-0.0"
    for func in ("p95", "p99"):
        assert window_value([sample(0, value=-0.0)], func)["value"] == 0.0


def test_distribution_multi_source_window():
    # Deduped window samples: [1, 3, 5] across two sources.
    metrics = [
        sample(0, "a", value=1.0),
        sample(100, "b", value=3.0),
        sample(200, "a", value=5.0),
    ]
    row = window_value(metrics, "median")
    assert row["value"] == 3.0
    assert row["count"] == 3
    assert row["sources"] == ["a", "b"]
    assert window_value(metrics, "p95")["value"] == 5.0


def test_distribution_window_start_and_sorting_unchanged():
    metrics = [
        sample(1900, value=9.0),
        sample(0, value=1.0),
        sample(100, value=2.0),
        sample(2000, name="zzz", value=5.0),
    ]
    result = process(
        payload(
            metrics,
            aggregations={"cpu.usage": "median", "zzz": "p99"},
        )
    )
    assert [(row["name"], row["timestamp_ms"], row["value"]) for row in result["series"]] == [
        ("cpu.usage", 0, 1.5),
        ("cpu.usage", 1000, 9.0),
        ("zzz", 2000, 5.0),
    ]


def test_unmapped_metric_still_uses_avg():
    metrics = [sample(0, value=2.0), sample(100, value=4.0)]
    result = process(payload(metrics, aggregations={"other": "median"}))
    assert result["series"][0]["value"] == 3.0


def test_no_aggregations_unchanged():
    metrics = [sample(0, value=2.0), sample(100, value=4.0)]
    result = process(payload(metrics))
    assert set(result) == {"series", "alerts", "suppressed_alert_ids"}
    assert result["series"][0]["value"] == 3.0


# -- interaction with source_quorum / source_weights / source_priority --------


PRIORITY = {"cpu.usage": ["a", "b"]}


def test_quorum_filters_before_percentile():
    # Quorum 2 not met -> window dropped even though p99 was requested.
    metrics = [sample(0, "a", value=1.0), sample(100, "a", value=9.0)]
    assert process(
        payload(
            metrics,
            aggregations={"cpu.usage": "p99"},
            source_quorum={"cpu.usage": 2},
        )
    )["series"] == []
    # Met by two sources: full deduped source set decides, p99 then runs.
    metrics.append(sample(200, "b", value=100.0))
    row = window_value(metrics, "p99", source_quorum={"cpu.usage": 2})
    assert row["value"] == 100.0
    assert row["sources"] == ["a", "b"]


def test_source_weights_ignore_aggregations():
    metrics = [
        sample(0, "a", value=2.0),
        sample(100, "b", value=8.0),
    ]
    # Weighted merge (a weight 3, b weight 1): (2*3+8*1)/4 = 3.5 regardless
    # of the requested p99.
    row = window_value(
        metrics,
        "p99",
        source_weights={"cpu.usage": {"a": 3.0, "b": 1.0}},
    )
    assert row["value"] == 3.5
    assert "weight_missing" not in row


def test_priority_percentile_uses_winning_source_samples_only():
    metrics = [
        sample(0, "a", value=1.0),
        sample(100, "a", value=3.0),
        sample(200, "a", value=5.0),
        sample(300, "b", value=1000.0),
    ]
    row = window_value(
        metrics, "median", source_priority=PRIORITY
    )
    assert row["value"] == 3.0  # median of [1,3,5], b never participates
    assert row["sources"] == ["a"]
    assert row["count"] == 3
    assert window_value(metrics, "p95", source_priority=PRIORITY)["value"] == 5.0
    assert window_value(metrics, "p99", source_priority=PRIORITY)["value"] == 5.0


def test_priority_failover_window_uses_distribution_function():
    # Window 0 only has backup source b; its samples feed the new functions.
    metrics = [
        sample(0, "b", value=2.0),
        sample(100, "b", value=8.0),
        sample(1000, "a", value=1.0),
    ]
    result = process(
        payload(
            metrics,
            aggregations={"cpu.usage": "median"},
            source_priority=PRIORITY,
        )
    )
    assert [(row["timestamp_ms"], row["value"], row["sources"]) for row in result["series"]] == [
        (0, 5.0, ["b"]),
        (1000, 1.0, ["a"]),
    ]


def test_priority_missing_row_unaffected_by_function():
    result = process(
        payload(
            [sample(0, "c", value=9.0)],
            aggregations={"cpu.usage": "p99"},
            source_priority=PRIORITY,
        )
    )
    assert result["series"][0] == {
        "name": "cpu.usage",
        "labels": {"host": "db-1"},
        "timestamp_ms": 0,
        "value": None,
        "count": 0,
        "sources": [],
        "priority_missing": True,
    }


# -- validation ---------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "median",
        ["median"],
        42,
        {"": "median"},
        {1: "median"},
        {"cpu.usage": ""},
        {"cpu.usage": "MEDIAN"},
        {"cpu.usage": "p95 "},
        {"cpu.usage": "p90"},
        {"cpu.usage": "percentile95"},
        {"cpu.usage": 5},
        {"cpu.usage": None},
        {"cpu.usage": ["median"]},
    ],
)
def test_invalid_aggregation_in_process(raw):
    with pytest.raises(ValueError, match="^invalid aggregation$"):
        process(payload([sample(0, "a")], aggregations=raw))


def test_invalid_aggregation_is_all_or_nothing():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0, "a"), sample(100, "b", value=9.0)],
        }
    )
    before = service.query_series()
    with pytest.raises(ValueError, match="^invalid aggregation$"):
        service.query_series(aggregations={"cpu.usage": "medianx"})
    with pytest.raises(ValueError, match="^invalid aggregation$"):
        service.query_series(aggregations={"cpu.usage": 99})
    # A rejected query changed neither stored state nor later valid queries.
    assert service.query_series() == before
    assert service.query_series(aggregations={"cpu.usage": "p99"})[0]["value"] == 9.0


# -- stateful service: patches, late data, retraction -------------------------


def test_service_percentile_recomputed_after_late_batch():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(i * 10, value=float(i)) for i in range(1, 11)],
        }
    )
    # Window [1..10]: n=10, p95/p99 rank 10 -> 10.0.
    rows = service.query_series(aggregations={"cpu.usage": "p95"})
    assert rows[0]["value"] == 10.0

    # A late batch contributes winning samples to the same window; the
    # percentile is recomputed from the current winner set.
    service.apply_batch(
        {
            "batch_id": "b2",
            "max_event_time_ms": 900,
            "metrics": [sample(100 + i, value=100.0 + i) for i in range(1, 11)],
        }
    )
    rows = service.query_series(aggregations={"cpu.usage": "median"})
    # 20 values 1..10 and 101..110 sorted; median = (10+101)/2 = 55.5
    assert rows[0]["value"] == 55.5
    rows = service.query_series(aggregations={"cpu.usage": "p99"})
    assert rows[0]["value"] == 110.0


def test_service_percentile_recomputed_after_retraction():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(i * 10, "a", value=float(i)) for i in range(1, 11)],
        }
    )
    # A higher-rank batch overrides every point of b1 with larger values.
    service.apply_batch(
        {
            "batch_id": "b2",
            "max_event_time_ms": 950,
            "metrics": [sample(i * 10, "a", value=100.0 + i) for i in range(1, 11)],
        }
    )
    rows = service.query_series(aggregations={"cpu.usage": "median"})
    assert rows[0]["value"] == 105.5  # median of 101..110

    service.retract_batch("b2")
    # b1's values win again; the function recomputes over restored winners.
    rows = service.query_series(aggregations={"cpu.usage": "median"})
    assert rows[0]["value"] == 5.5  # median of 1..10
    rows = service.query_series(aggregations={"cpu.usage": "p95"})
    assert rows[0]["value"] == 10.0


def test_service_batch_idempotency_and_rank_unaffected():
    service = MetricBatchService(downsample_ms=1000)
    request = {
        "batch_id": "b1",
        "max_event_time_ms": 900,
        "metrics": [sample(i * 10, value=float(i)) for i in range(1, 11)],
    }
    first = service.apply_batch(request)
    duplicate = service.apply_batch(json.loads(json.dumps(request)))
    assert duplicate == {
        "batch_id": "b1",
        "status": "applied",
        "affected_streams": 0,
        "recomputed_windows": 0,
    }
    assert first["status"] == "applied"
    # Arrival-order independence: batches applied in either order agree.
    other = MetricBatchService(downsample_ms=1000)
    other.apply_batch(
        {
            "batch_id": "late",
            "max_event_time_ms": 950,
            "metrics": [sample(5, value=42.0)],
        }
    )
    other.apply_batch(request)
    service.apply_batch(
        {
            "batch_id": "late",
            "max_event_time_ms": 950,
            "metrics": [sample(5, value=42.0)],
        }
    )
    assert service.query_series(aggregations={"cpu.usage": "p99"}) == other.query_series(
        aggregations={"cpu.usage": "p99"}
    )


def test_service_get_default_query_does_not_read_aggregations():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0, value=1.0), sample(100, value=3.0)],
        }
    )
    row = service.query_series()[0]
    assert set(row) == {"name", "labels", "timestamp_ms", "value", "count", "sources"}
    assert row["value"] == 2.0  # avg, never a percentile
    assert service.query_alerts()["suppressed_alert_ids"] == []


# -- CLI ----------------------------------------------------------------------


def test_cli_distribution_outputs_row(tmp_path):
    request_file = tmp_path / "request.json"
    metrics = [sample(i, value=float(v)) for i, v in enumerate([4.0, 1.0, 3.0, 2.0])]
    request_file.write_text(
        json.dumps(payload(metrics, aggregations={"cpu.usage": "median"})),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    out = json.loads(completed.stdout)
    assert out["series"][0]["value"] == 2.5


@pytest.mark.parametrize("func", ["medianx", "p90", "P95"])
def test_cli_invalid_aggregation_exits_2(tmp_path, func):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(payload([sample(0)], aggregations={"cpu.usage": func})),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert completed.stderr.strip().endswith("invalid aggregation")
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


def test_http_process_accepts_new_functions(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/process",
        payload(
            [sample(i, value=float(v)) for i, v in enumerate([1.0, 2.0, 3.0, 4.0])],
            aggregations={"cpu.usage": "median"},
        ),
    )
    assert status == 200
    assert body["series"][0]["value"] == 2.5


def test_http_process_invalid_aggregation_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post("/process", payload([sample(0)], aggregations={"cpu.usage": "p90"}))
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid aggregation"}


def test_http_query_accepts_new_functions(http_service):
    service, post, _get = http_service
    post(
        "/v1/metric_batches",
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(i, value=float(v)) for i, v in enumerate(range(1, 21))],
        },
    )
    status, body = post("/v1/query", {"aggregations": {"cpu.usage": "p95"}})
    assert status == 200
    assert body["series"][0]["value"] == 19.0
    status, body = post("/v1/query", {"aggregations": {"cpu.usage": "p99"}})
    assert status == 200
    assert body["series"][0]["value"] == 20.0


def test_http_query_invalid_aggregation_returns_400_and_keeps_state(http_service):
    service, post, _get = http_service
    post(
        "/v1/metric_batches",
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, value=1.0)]},
    )
    status, body = post("/v1/query", {"aggregations": {"cpu.usage": "median!"}})
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid aggregation"}
    # Non-mapping aggregations fail the same way.
    status, body = post("/v1/query", {"aggregations": ["median"]})
    assert status == 400
    assert body["message"] == "invalid aggregation"
    # State and valid queries still work.
    status, body = post("/v1/query", {"aggregations": {"cpu.usage": "median"}})
    assert status == 200
    assert body["series"][0]["value"] == 1.0
    assert len(service.query_series()) == 1


def test_http_get_endpoints_ignore_aggregations(http_service):
    _service, post, get = http_service
    post(
        "/v1/metric_batches",
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0, value=1.0), sample(100, value=9.0)],
        },
    )
    status, body = get("/v1/series")
    assert status == 200
    assert body["series"][0]["value"] == 5.0  # avg
    status, body = get("/v1/alerts")
    assert status == 200
    assert body["suppressed_alert_ids"] == []
