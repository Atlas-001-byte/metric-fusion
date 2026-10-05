"""Tests for distribution window aggregations (median/p95/p99)."""

import json
import math
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from urllib import error as urllib_error
from urllib import request as urllib_request

import pytest

from metric_fusion import MetricBatchService, process
from metric_fusion.server import _make_handler


def sample(ts, source="a", name="cpu.usage", value=1.0, labels=None):
    return {
        "source": source,
        "name": name,
        "labels": {"host": "db-1"} if labels is None else labels,
        "value": value,
        "timestamp_ms": ts,
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


# -- process(): median --------------------------------------------------------


def test_median_odd_sample_count():
    metrics = [sample(0, value=1.0), sample(10, value=5.0), sample(20, value=3.0)]
    result = process(payload(metrics, aggregations={"cpu.usage": "median"}))
    assert result["series"][0]["value"] == 3.0


def test_median_even_sample_count_averages_middle_pair():
    metrics = [
        sample(0, value=1.0),
        sample(10, value=2.0),
        sample(20, value=3.0),
        sample(30, value=10.0),
    ]
    result = process(payload(metrics, aggregations={"cpu.usage": "median"}))
    assert result["series"][0]["value"] == 2.5


def test_median_independent_of_arrival_order():
    metrics_a = [
        sample(0, "a", value=1.0),
        sample(10, "b", value=7.0),
        sample(20, "c", value=3.0),
        sample(30, "a", value=9.0),
    ]
    metrics_b = list(reversed(metrics_a))
    rows_a = process(payload(metrics_a, aggregations={"cpu.usage": "median"}))["series"]
    rows_b = process(payload(metrics_b, aggregations={"cpu.usage": "median"}))["series"]
    assert rows_a == rows_b
    assert rows_a[0]["value"] == 5.0  # sorted [1,3,7,9] -> (3+7)/2


def test_median_uses_deduplicated_samples():
    metrics = [
        sample(0, "a", value=4.0),
        sample(0, "a", value=6.0),  # same point key: later occurrence wins
        sample(10, "b", value=8.0),
    ]
    result = process(payload(metrics, aggregations={"cpu.usage": "median"}))
    row = result["series"][0]
    assert row["value"] == 7.0  # dedup samples [6, 8]
    assert row["count"] == 2
    assert row["sources"] == ["a", "b"]


def test_median_single_sample():
    result = process(
        payload([sample(0, value=42.0)], aggregations={"cpu.usage": "median"})
    )
    assert result["series"][0]["value"] == 42.0


def test_median_rounding_and_negative_zero_normalized():
    metrics = [sample(0, value=-1e-9), sample(10, value=0.0)]
    result = process(payload(metrics, aggregations={"cpu.usage": "median"}))
    value = result["series"][0]["value"]
    assert value == 0.0
    assert math.copysign(1.0, value) == 1.0


# -- process(): percentiles ---------------------------------------------------


def test_p95_nearest_rank_without_interpolation():
    # n=20, values 1..20: ceil(0.95*20) = 19 -> 19th ordered value.
    metrics = [sample(ts, value=float(ts + 1)) for ts in range(20)]
    result = process(payload(metrics, aggregations={"cpu.usage": "p95"}))
    assert result["series"][0]["value"] == 19.0


def test_p99_nearest_rank_without_interpolation():
    # n=20: ceil(0.99*20) = ceil(19.8) = 20 -> maximum.
    metrics = [sample(ts, value=float(ts + 1)) for ts in range(20)]
    result = process(payload(metrics, aggregations={"cpu.usage": "p99"}))
    assert result["series"][0]["value"] == 20.0


def test_percentiles_with_n_100():
    metrics = [sample(ts, value=float(ts + 1)) for ts in range(100)]
    rows = process(payload(metrics, aggregations={"cpu.usage": "p95"}))["series"]
    assert rows[0]["value"] == 95.0
    rows = process(payload(metrics, aggregations={"cpu.usage": "p99"}))["series"]
    assert rows[0]["value"] == 99.0


def test_percentiles_small_n_collapse_to_max():
    # n=10: ceil(9.5) = 10 and ceil(9.9) = 10.
    metrics = [sample(ts, value=float(ts + 1)) for ts in range(10)]
    rows = process(payload(metrics, aggregations={"cpu.usage": "p95"}))["series"]
    assert rows[0]["value"] == 10.0
    rows = process(payload(metrics, aggregations={"cpu.usage": "p99"}))["series"]
    assert rows[0]["value"] == 10.0


def test_percentile_single_sample():
    for func in ("p95", "p99"):
        result = process(
            payload([sample(0, value=7.0)], aggregations={"cpu.usage": func})
        )
        assert result["series"][0]["value"] == 7.0


def test_percentiles_independent_of_arrival_order():
    metrics = [
        sample(ts, source=("a" if ts % 2 else "b"), value=float((ts * 37) % 101))
        for ts in range(40)
    ]
    for func in ("median", "p95", "p99"):
        rows_a = process(payload(metrics, aggregations={"cpu.usage": func}))["series"]
        rows_b = process(
            payload(list(reversed(metrics)), aggregations={"cpu.usage": func})
        )["series"]
        assert rows_a == rows_b


# -- row shape, defaults and composition --------------------------------------


def test_distribution_row_keeps_plain_window_fields():
    metrics = [sample(ts, value=float(ts)) for ts in range(5)]
    result = process(payload(metrics, aggregations={"cpu.usage": "p95"}))
    assert set(result["series"][0]) == {
        "name",
        "labels",
        "timestamp_ms",
        "value",
        "count",
        "sources",
    }
    assert result["series"][0]["count"] == 5


def test_unmapped_metric_still_uses_avg():
    metrics = [sample(0, value=2.0), sample(10, value=4.0)]
    result = process(payload(metrics, aggregations={"other.metric": "median"}))
    assert result["series"][0]["value"] == 3.0


def test_absent_aggregations_unchanged():
    metrics = [sample(0, value=2.0), sample(10, value=4.0)]
    assert process(payload(metrics)) == process(
        payload(metrics, aggregations={"cpu.usage": "avg"})
    )


def test_quorum_filters_on_full_deduped_source_set_before_distribution():
    metrics = [
        sample(0, "a", value=1.0),
        sample(10, "a", value=2.0),
        sample(20, "b", value=100.0),
    ]
    result = process(
        payload(
            metrics,
            aggregations={"cpu.usage": "median"},
            source_quorum={"cpu.usage": 3},
        )
    )
    assert result["series"] == []
    result = process(
        payload(
            metrics,
            aggregations={"cpu.usage": "median"},
            source_quorum={"cpu.usage": 2},
        )
    )
    # Full source set passes; median is over all deduped samples.
    assert result["series"][0]["value"] == 2.0


def test_source_weights_hit_ignores_aggregations():
    metrics = [
        sample(0, "a", value=1.0),
        sample(10, "a", value=3.0),
        sample(20, "b", value=100.0),
    ]
    result = process(
        payload(
            metrics,
            aggregations={"cpu.usage": "p99"},
            source_weights={"cpu.usage": {"a": 1.0, "b": 0.0}},
        )
    )
    row = result["series"][0]
    assert row["value"] == 2.0  # weighted mean of a's samples, p99 ignored
    assert "weight_missing" not in row


# -- source_priority with distribution functions ------------------------------


PRIORITY = {"cpu.usage": ["a", "b"]}


def test_priority_median_uses_only_winning_source_samples():
    metrics = [
        sample(0, "a", value=1.0),
        sample(10, "a", value=5.0),
        sample(20, "b", value=100.0),
    ]
    result = process(
        payload(metrics, aggregations={"cpu.usage": "median"}, source_priority=PRIORITY)
    )
    row = result["series"][0]
    assert row["value"] == 3.0  # median of a's [1, 5]
    assert row["count"] == 2
    assert row["sources"] == ["a"]


def test_priority_p95_after_failover():
    metrics = [sample(ts, "b", value=float(ts + 1)) for ts in range(20)]
    result = process(
        payload(metrics, aggregations={"cpu.usage": "p95"}, source_priority=PRIORITY)
    )
    row = result["series"][0]
    assert row["value"] == 19.0
    assert row["sources"] == ["b"]


# -- stateful service: recompute after patches/retractions --------------------


def test_service_distribution_recomputed_after_late_batch_and_retraction():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0, "a", value=1.0), sample(10, "a", value=2.0)],
        }
    )
    rows = service.query_series(aggregations={"cpu.usage": "median"})
    assert rows[0]["value"] == 1.5

    service.apply_batch(
        {
            "batch_id": "b2",
            "max_event_time_ms": 900,
            "metrics": [sample(20, "a", value=9.0)],
        }
    )
    rows = service.query_series(aggregations={"cpu.usage": "median"})
    assert rows[0]["value"] == 2.0  # [1, 2, 9]

    rows = service.query_series(aggregations={"cpu.usage": "p95"})
    assert rows[0]["value"] == 9.0  # ceil(0.95*3) = 3

    service.retract_batch("b2")
    rows = service.query_series(aggregations={"cpu.usage": "median"})
    assert rows[0]["value"] == 1.5
    rows = service.query_series(aggregations={"cpu.usage": "p99"})
    assert rows[0]["value"] == 2.0  # ceil(0.99*2) = 2


def test_service_distribution_follows_winning_batch_rank_samples():
    service = MetricBatchService(downsample_ms=1000)
    # Lower-rank batch writes the point first; the later higher-rank batch
    # overrides the same point, and the percentile must use the winner.
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 800,
            "metrics": [sample(0, "a", value=1.0)],
        }
    )
    service.apply_batch(
        {
            "batch_id": "b2",
            "max_event_time_ms": 900,
            "metrics": [sample(0, "a", value=8.0), sample(10, "a", value=9.0)],
        }
    )
    rows = service.query_series(aggregations={"cpu.usage": "median"})
    assert rows[0]["value"] == 8.5  # winning samples [8, 9]
    service.retract_batch("b2")
    rows = service.query_series(aggregations={"cpu.usage": "median"})
    assert rows[0]["value"] == 1.0  # only the restored rank winner remains


# -- validation: library ------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        {"cpu.usage": "mean"},
        {"cpu.usage": "median "},
        {"cpu.usage": 123},
        {"cpu.usage": None},
        {"": "median"},
        ["not", "a", "mapping"],
        "median",
    ],
)
def test_process_rejects_invalid_aggregations(bad):
    with pytest.raises(ValueError, match="^invalid aggregation$"):
        process(payload([sample(0)], aggregations=bad))


@pytest.mark.parametrize(
    "bad",
    [
        {"cpu.usage": "p100"},
        {"cpu.usage": 7},
        {"": "p95"},
        {"cpu.usage": ["median"]},
    ],
)
def test_query_series_rejects_invalid_aggregations_without_state_change(bad):
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0, "a", value=2.0), sample(10, "a", value=4.0)],
        }
    )
    before = service.query_series()
    with pytest.raises(ValueError, match="^invalid aggregation$"):
        service.query_series(aggregations=bad)
    assert service.query_series() == before


# -- validation: HTTP ----------------------------------------------------------


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


def test_http_query_distribution_functions(http_service):
    service, post, _get = http_service
    post(
        "/v1/metric_batches",
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(ts, "a", value=float(ts + 1)) for ts in range(20)],
        },
    )
    status, body = post("/v1/query", {"aggregations": {"cpu.usage": "p99"}})
    assert status == 200
    assert body["series"][0]["value"] == 20.0


def test_http_query_invalid_aggregation_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post("/v1/query", {"aggregations": {"cpu.usage": "median/p95"}})
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid aggregation"}


def test_http_process_invalid_aggregation_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/process", payload([sample(0)], aggregations={"cpu.usage": "histogram"})
    )
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid aggregation"}


def test_http_get_series_does_not_read_query_aggregations(http_service):
    service, post, get = http_service
    post(
        "/v1/metric_batches",
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [
                sample(0, "a", value=2.0),
                sample(10, "a", value=4.0),
                sample(20, "a", value=10.0),
            ],
        },
    )
    status, body = get("/v1/series")
    assert status == 200
    # GET /v1/series always aggregates with the default avg; median would be 4.0.
    assert body["series"][0]["value"] == round(16.0 / 3.0, 6)


# -- validation: CLI -----------------------------------------------------------


def test_cli_invalid_aggregation_exits_2(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(payload([sample(0)], aggregations={"cpu.usage": "p50"})),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "invalid aggregation" in completed.stderr


def test_cli_median_outputs_row(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(
            payload(
                [sample(0, value=1.0), sample(10, value=3.0)],
                aggregations={"cpu.usage": "median"},
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
    assert json.loads(completed.stdout)["series"][0]["value"] == 2.0
