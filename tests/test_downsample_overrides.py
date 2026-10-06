"""Tests for per-metric downsample periods (downsample_overrides)."""

import json
import subprocess
import sys

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


# -- process(): per-metric windowing -------------------------------------------


def test_override_rewindows_matching_metric():
    # Default period would put 100 and 900 in window 0; period 500 splits them.
    result = process(
        payload(
            [sample(100, value=1.0), sample(900, value=3.0)],
            downsample_overrides={"cpu.usage": 500},
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
        },
        {
            "name": "cpu.usage",
            "labels": {"host": "db-1"},
            "timestamp_ms": 500,
            "value": 3.0,
            "count": 1,
            "sources": ["a"],
        },
    ]


def test_override_aggregates_within_override_window():
    result = process(
        payload(
            [sample(100, value=1.0), sample(400, value=2.0), sample(600, value=4.0)],
            downsample_overrides={"cpu.usage": 500},
        )
    )
    assert [(row["timestamp_ms"], row["value"], row["count"]) for row in result["series"]] == [
        (0, 1.5, 2),
        (500, 4.0, 1),
    ]


def test_unconfigured_metrics_keep_default_period():
    metrics = [
        sample(100, name="cpu.usage", value=1.0),
        sample(900, name="cpu.usage", value=3.0),
        sample(100, name="mem.usage", value=2.0),
        sample(900, name="mem.usage", value=4.0),
    ]
    result = process(payload(metrics, downsample_overrides={"cpu.usage": 500}))
    by_name = {}
    for row in result["series"]:
        by_name.setdefault(row["name"], []).append((row["timestamp_ms"], row["value"]))
    assert by_name["cpu.usage"] == [(0, 1.0), (500, 3.0)]
    assert by_name["mem.usage"] == [(0, 3.0)]


def test_no_override_unchanged():
    metrics = [sample(100, value=1.0), sample(900, value=3.0)]
    baseline = process(payload(metrics))
    unmatched = process(payload(metrics, downsample_overrides={"other.metric": 500}))
    assert baseline["series"] == unmatched["series"]
    assert baseline["series"][0]["value"] == 2.0
    assert set(unmatched) == {"series", "alerts", "suppressed_alert_ids"}


def test_override_combines_with_aggregation_selection():
    result = process(
        payload(
            [sample(100, value=5.0), sample(200, value=1.0), sample(300, value=3.0)],
            aggregations={"cpu.usage": "max"},
            downsample_overrides={"cpu.usage": 500},
        )
    )
    assert result["series"][0]["value"] == 5.0
    assert result["series"][0]["timestamp_ms"] == 0


def test_override_combines_with_source_quorum_weights_priority():
    metrics = [
        sample(100, "a", value=2.0),
        sample(200, "b", value=4.0),
    ]
    weighted = process(
        payload(
            metrics,
            source_weights={"cpu.usage": {"a": 1.0, "b": 3.0}},
            downsample_overrides={"cpu.usage": 500},
        )
    )
    assert weighted["series"][0]["value"] == round((2.0 + 12.0) / 4.0, 6)

    priority = process(
        payload(
            metrics,
            source_priority={"cpu.usage": ["b", "a"]},
            downsample_overrides={"cpu.usage": 500},
        )
    )
    assert priority["series"][0]["value"] == 4.0
    assert priority["series"][0]["sources"] == ["b"]

    quorum = process(
        payload(
            metrics,
            source_quorum={"cpu.usage": 3},
            downsample_overrides={"cpu.usage": 500},
        )
    )
    assert quorum["series"] == []


def test_gap_fill_uses_metric_own_period():
    # cpu.usage has period 500 with output windows at 0 and 1500: the fill
    # rows land on the 500-grid (500, 1000), not the default 1000-grid.
    metrics = [sample(0, value=1.0), sample(1500, value=2.0)]
    result = process(
        payload(
            metrics,
            gap_fill={"cpu.usage": 2000},
            downsample_overrides={"cpu.usage": 500},
        )
    )
    assert [(row["timestamp_ms"], row["value"], row["count"]) for row in result["series"]] == [
        (0, 1.0, 1),
        (500, 1.0, 0),
        (1000, 1.0, 0),
        (1500, 2.0, 1),
    ]


def test_gap_fill_periods_differ_per_metric():
    metrics = [
        sample(0, name="cpu.usage", value=1.0),
        sample(1500, name="cpu.usage", value=2.0),
        sample(0, name="mem.usage", value=10.0),
        sample(2000, name="mem.usage", value=20.0),
    ]
    result = process(
        payload(
            metrics,
            gap_fill={"cpu.usage": 2000, "mem.usage": 2000},
            downsample_overrides={"cpu.usage": 500},
        )
    )
    by_name = {}
    for row in result["series"]:
        by_name.setdefault(row["name"], []).append(row["timestamp_ms"])
    assert by_name["cpu.usage"] == [0, 500, 1000, 1500]
    # mem.usage keeps the default 1000ms period.
    assert by_name["mem.usage"] == [0, 1000, 2000]


# -- process(): validation ------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        ["cpu.usage"],  # not a mapping
        "500",  # not a mapping
        500,  # not a mapping
        {"": 500},  # empty metric name
        {500: 500},  # non-string metric name
        {"cpu.usage": True},  # boolean
        {"cpu.usage": 0},  # zero
        {"cpu.usage": -500},  # negative
        {"cpu.usage": 500.0},  # float
        {"cpu.usage": float("inf")},  # non-finite
        {"cpu.usage": float("nan")},  # non-finite
        {"cpu.usage": "500"},  # non-numeric
    ],
)
def test_invalid_overrides_rejected(overrides):
    with pytest.raises(ValueError, match="invalid downsample_override"):
        process(payload([sample(0)], downsample_overrides=overrides))


def test_invalid_override_leaves_no_partial_result():
    # Even a request whose other options are valid fails as a whole.
    with pytest.raises(ValueError, match="invalid downsample_override"):
        process(
            payload(
                [sample(0, value=1.0)],
                aggregations={"cpu.usage": "max"},
                downsample_overrides={"cpu.usage": -1},
            )
        )


# -- MetricBatchService.query_series -------------------------------------------


def batch_request(batch_id, metrics, max_event_time_ms, alerts=None):
    return {
        "batch_id": batch_id,
        "max_event_time_ms": max_event_time_ms,
        "metrics": metrics,
        "alerts": alerts or [],
    }


def test_query_series_recomputes_override_metric():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        batch_request(
            "b1",
            [sample(100, value=1.0), sample(900, value=3.0)],
            900,
        )
    )
    # Default windows: one bucket at 0.
    default_rows = service.query_series()
    assert [(row["timestamp_ms"], row["value"]) for row in default_rows] == [(0, 2.0)]
    # Override windows: recomputed from the winning samples at period 500.
    rows = service.query_series(downsample_overrides={"cpu.usage": 500})
    assert [(row["timestamp_ms"], row["value"]) for row in rows] == [(0, 1.0), (500, 3.0)]


def test_query_series_override_reflects_late_patch():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(batch_request("b1", [sample(100, value=1.0)], 100))
    service.apply_batch(batch_request("b2", [sample(100, value=9.0)], 200))
    rows = service.query_series(downsample_overrides={"cpu.usage": 500})
    assert [(row["timestamp_ms"], row["value"]) for row in rows] == [(0, 9.0)]


def test_query_series_override_reflects_retraction():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(batch_request("b1", [sample(100, value=1.0)], 100))
    service.apply_batch(batch_request("b2", [sample(100, value=9.0)], 200))
    service.retract_batch("b2")
    rows = service.query_series(downsample_overrides={"cpu.usage": 500})
    assert [(row["timestamp_ms"], row["value"]) for row in rows] == [(0, 1.0)]


def test_query_series_override_only_rewindows_listed_metrics():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        batch_request(
            "b1",
            [
                sample(100, name="cpu.usage", value=1.0),
                sample(900, name="cpu.usage", value=3.0),
                sample(100, name="mem.usage", value=2.0),
                sample(900, name="mem.usage", value=4.0),
            ],
            900,
        )
    )
    rows = service.query_series(downsample_overrides={"cpu.usage": 500})
    by_name = {}
    for row in rows:
        by_name.setdefault(row["name"], []).append((row["timestamp_ms"], row["value"]))
    assert by_name["cpu.usage"] == [(0, 1.0), (500, 3.0)]
    assert by_name["mem.usage"] == [(0, 3.0)]


def test_query_series_override_combines_with_query_options():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        batch_request("b1", [sample(0, "a", value=2.0), sample(100, "b", value=4.0)], 100)
    )
    service.apply_batch(batch_request("b2", [sample(1500, "a", value=8.0)], 1500))
    rows = service.query_series(
        aggregations={"cpu.usage": "sum"},
        gap_fill={"cpu.usage": 1000},
        downsample_overrides={"cpu.usage": 500},
    )
    assert [(row["timestamp_ms"], row["value"], row["count"]) for row in rows] == [
        (0, 6.0, 2),
        (500, 6.0, 0),
        (1000, 6.0, 0),
        (1500, 8.0, 1),
    ]


def test_query_series_override_quorum_uses_override_windows():
    service = MetricBatchService(downsample_ms=1000)
    # One source in the first 500ms window, two in the second.
    service.apply_batch(
        batch_request(
            "b1",
            [sample(100, "a", value=1.0), sample(600, "a", value=2.0), sample(700, "b", value=4.0)],
            700,
        )
    )
    rows = service.query_series(
        source_quorum={"cpu.usage": 2},
        downsample_overrides={"cpu.usage": 500},
    )
    assert [(row["timestamp_ms"], row["value"]) for row in rows] == [(500, 3.0)]


def test_batch_accounting_ignores_overrides():
    # Apply/retract bookkeeping always uses the constructor downsample_ms.
    service = MetricBatchService(downsample_ms=1000)
    applied = service.apply_batch(
        batch_request("b1", [sample(100, value=1.0), sample(900, value=3.0)], 900)
    )
    assert applied == {
        "batch_id": "b1",
        "status": "applied",
        "affected_streams": 1,
        "recomputed_windows": 1,
    }
    retracted = service.retract_batch("b1")
    assert retracted["recomputed_windows"] == 1
    assert retracted["affected_streams"] == 1


def test_query_series_invalid_overrides_rejected():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(batch_request("b1", [sample(0)], 0))
    for bad in (
        ["cpu.usage"],
        {"": 500},
        {"cpu.usage": True},
        {"cpu.usage": 0},
        {"cpu.usage": -1},
        {"cpu.usage": 1.5},
        {"cpu.usage": float("inf")},
    ):
        with pytest.raises(ValueError, match="invalid downsample_override"):
            service.query_series(downsample_overrides=bad)
    # A failed query changes nothing: the service still answers normally.
    assert len(service.query_series()) == 1


# -- CLI ------------------------------------------------------------------------


def test_cli_invalid_override_exits_2(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(payload([sample(0)], downsample_overrides={"cpu.usage": 0})),
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "invalid downsample_override" in result.stderr
    assert result.stdout == ""
