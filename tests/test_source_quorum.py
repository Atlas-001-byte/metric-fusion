"""Tests for optional source-quorum window filtering."""

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


def test_quorum_drops_under_covered_windows_only():
    result = process(
        payload(
            [sample(0, "a"), sample(100, "b"), sample(1000, "a")],
            source_quorum={"cpu.usage": 2},
        )
    )
    assert [row["timestamp_ms"] for row in result["series"]] == [0]
    assert result["series"][0]["sources"] == ["a", "b"]
    assert result["series"][0]["count"] == 2


def test_quorum_uses_distinct_sources_not_sample_count():
    result = process(
        payload(
            [sample(0, "a"), sample(100, "a"), sample(200, "a")],
            source_quorum={"cpu.usage": 2},
        )
    )
    assert result["series"] == []


def test_quorum_counts_after_dedup():
    # Repeated identical points collapse before coverage is judged.
    result = process(
        payload(
            [sample(0, "a"), sample(0, "a"), sample(0, "b")],
            source_quorum={"cpu.usage": 3},
        )
    )
    assert result["series"] == []
    result = process(
        payload(
            [sample(0, "a"), sample(0, "a"), sample(0, "b")],
            source_quorum={"cpu.usage": 2},
        )
    )
    assert len(result["series"]) == 1
    assert result["series"][0]["sources"] == ["a", "b"]


def test_quorum_equality_passes_without_fill_points():
    result = process(
        payload(
            [sample(1000, "a"), sample(1100, "b"), sample(2000, "a")],
            source_quorum={"cpu.usage": 2},
        )
    )
    assert [row["timestamp_ms"] for row in result["series"]] == [1000]


def test_quorum_scoped_by_name_and_labels():
    result = process(
        payload(
            [
                sample(0, "a", name="x"),
                sample(0, "b", name="x"),
                sample(0, "a", name="y"),
                sample(0, "a", labels={"host": "other"}),
                sample(0, "b", labels={"host": "other"}),
            ],
            source_quorum={"x": 2},
        )
    )
    names_labels = sorted((row["name"], row["labels"]["host"]) for row in result["series"])
    assert names_labels == [("cpu.usage", "other"), ("x", "db-1"), ("y", "db-1")]


def test_unmatched_or_absent_quorum_leaves_output_unchanged():
    without = process(payload([sample(0, "a")]))
    unmatched = process(payload([sample(0, "a")], source_quorum={"other": 3}))
    assert without["series"] == unmatched["series"]
    assert set(without) == {"series", "alerts", "suppressed_alert_ids"}


def test_quorum_with_aggregations_keeps_value_semantics():
    result = process(
        payload(
            [sample(0, "a", value=3.0), sample(0, "b", value=5.0),
             sample(1000, "a", value=-0.0)],
            aggregations={"cpu.usage": "sum"},
            source_quorum={"cpu.usage": 2},
        )
    )
    assert [row["value"] for row in result["series"]] == [8.0]
    # An under-covered window is dropped even when its metric has an aggregation.
    result = process(
        payload([sample(0, "a", value=3.0)],
                aggregations={"cpu.usage": "max"},
                source_quorum={"cpu.usage": 2})
    )
    assert result["series"] == []


def test_alerts_are_unaffected_by_unmet_quorum():
    alert = {
        "source": "a",
        "name": "cpu.usage",
        "labels": {"host": "db-1"},
        "alert_id": "a1",
        "rule": "cpu-high",
        "timestamp_ms": 0,
        "severity": "warning",
    }
    request = payload([sample(0, "a")])
    request["alerts"] = [alert]
    request["source_quorum"] = {"cpu.usage": 5}
    result = process(request)
    assert result["series"] == []
    assert result["alerts"] == [
        {"alert_id": "a1", "severity": "warning", "suppressed": False}
    ]
    assert result["suppressed_alert_ids"] == []


@pytest.mark.parametrize(
    "raw",
    [
        "not-a-mapping",
        ["not-a-mapping"],
        {"": 1},
        {"cpu.usage": 0},
        {"cpu.usage": -1},
        {"cpu.usage": 1.5},
        {"cpu.usage": True},
        {"cpu.usage": False},
        {"cpu.usage": None},
        {"cpu.usage": "2"},
        {1: 1},
    ],
)
def test_invalid_source_quorum_in_process(raw):
    with pytest.raises(ValueError, match="^invalid source_quorum$"):
        process(payload([sample(0, "a")], source_quorum=raw))


# -- MetricBatchService --------------------------------------------------------


def test_service_query_quorum_and_validation():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "a"), sample(100, "b")]}
    )
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 1900, "metrics": [sample(1000, "a")]}
    )
    assert [
        row["timestamp_ms"]
        for row in service.query_series(source_quorum={"cpu.usage": 2})
    ] == [0]
    assert [
        row["timestamp_ms"]
        for row in service.query_series(source_quorum={"cpu.usage": 1})
    ] == [0, 1000]

    for raw in ({"x": 0}, {"x": True}, {"x": 1.5}, "nope", {"": 1}):
        with pytest.raises(ValueError, match="^invalid source_quorum$"):
            service.query_series(source_quorum=raw)


def test_service_quorum_recomputed_after_correction_and_retraction():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 1900, "metrics": [sample(1000, "a")]}
    )
    assert service.query_series(source_quorum={"cpu.usage": 2}) == []

    # Late correction brings a second source into the window.
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 1900, "metrics": [sample(1100, "b")]}
    )
    rows = service.query_series(source_quorum={"cpu.usage": 2})
    assert [row["timestamp_ms"] for row in rows] == [1000]

    # Retracting the correction drops the window back below the threshold.
    service.retract_batch("b2")
    assert service.query_series(source_quorum={"cpu.usage": 2}) == []
    assert [
        row["timestamp_ms"]
        for row in service.query_series(source_quorum={"cpu.usage": 1})
    ] == [1000]


def test_service_full_queries_and_alerts_ignore_quorum():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a")]}
    )
    assert len(service.query_series()) == 1
    alerts = service.query_alerts()
    assert alerts["suppressed_alert_ids"] == []
