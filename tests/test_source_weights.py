"""Tests for optional per-target source-weight merging."""

import math

import pytest

from metric_fusion import (
    BatchError,
    MetricBatchService,
    SourceWeightError,
    process,
)


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


WEIGHTS = {"cpu.usage": {"a": 1, "b": 3}}


# -- weighted value -------------------------------------------------------------


def test_weighted_average_basic():
    # (1*1 + 5*3) / (1 + 3) = 4.0
    result = process(
        payload([sample(0, "a", 1.0), sample(100, "b", 5.0)], source_weights=WEIGHTS)
    )
    assert len(result["series"]) == 1
    row = result["series"][0]
    assert row["value"] == 4.0
    assert row["sources"] == ["a", "b"]
    assert row["count"] == 2
    assert row["timestamp_ms"] == 0
    assert result["weight_missing_windows"] == []


def test_weighted_result_equals_weighted_sum_over_effective_weight():
    weights = {"cpu.usage": {"a": 2.5, "b": 0.5, "c": 2.0}}
    result = process(
        payload(
            [sample(0, "a", 4.0), sample(100, "b", 8.0), sample(200, "c", 10.0)],
            source_weights=weights,
        )
    )
    # (4*2.5 + 8*0.5 + 10*2) / 5 = 34/5 = 6.8
    assert result["series"][0]["value"] == 6.8


def test_default_equal_weight_unchanged_when_absent():
    result = process(payload([sample(0, "a", 1.0), sample(100, "b", 5.0)]))
    assert result["series"][0]["value"] == 3.0
    assert "weight_missing_windows" not in result
    # An empty mapping is equivalent to the feature being off.
    result_empty = process(
        payload([sample(0, "a", 1.0), sample(100, "b", 5.0)], source_weights={})
    )
    assert result_empty["series"][0]["value"] == 3.0
    assert "weight_missing_windows" not in result_empty


def test_unweighted_target_keeps_equal_weight_alongside_weighted_target():
    metrics = [
        sample(0, "a", 1.0, name="w"),
        sample(100, "b", 5.0, name="w"),
        sample(0, "a", 2.0, name="plain"),
        sample(100, "b", 4.0, name="plain"),
    ]
    result = process(payload(metrics, source_weights={"w": {"a": 1, "b": 3}}))
    rows = {row["name"]: row for row in result["series"]}
    assert rows["w"]["value"] == 4.0  # weighted
    assert rows["plain"]["value"] == 3.0  # equal-weight average


def test_participating_sources_can_be_fewer_than_known():
    # Only source "a" is listed; source "b" samples exist but never contribute.
    result = process(
        payload(
            [sample(0, "a", 7.0), sample(100, "b", 99.0)],
            source_weights={"cpu.usage": {"a": 2}},
        )
    )
    row = result["series"][0]
    assert row["value"] == 7.0
    assert row["sources"] == ["a"]
    assert row["count"] == 1


def test_partial_source_presence_normalizes_over_present_weight_only():
    # Source "b" is absent from the window; the result normalizes over "a" only.
    result = process(
        payload([sample(0, "a", 6.0)], source_weights=WEIGHTS)
    )
    assert result["series"][0]["value"] == 6.0
    assert result["series"][0]["sources"] == ["a"]


def test_zero_weight_source_counts_availability_but_not_value():
    result = process(
        payload(
            [sample(0, "a", 6.0), sample(100, "b", 99.0)],
            source_weights={"cpu.usage": {"a": 1, "b": 0}},
        )
    )
    row = result["series"][0]
    assert row["value"] == 6.0  # b contributes no value
    assert row["sources"] == ["a", "b"]  # but is reported as available
    assert row["count"] == 1  # only positive-weight points count
    assert result["weight_missing_windows"] == []


def test_all_zero_weights_mark_window_weight_missing_without_value():
    result = process(
        payload(
            [sample(0, "a", 6.0), sample(100, "b", 99.0)],
            source_weights={"cpu.usage": {"a": 0, "b": 0}},
        )
    )
    assert result["series"] == []
    assert result["weight_missing_windows"] == [
        {"name": "cpu.usage", "labels": {"host": "db-1"}, "timestamp_ms": 0}
    ]


def test_only_zero_weight_source_is_weight_missing():
    result = process(
        payload([sample(0, "b", 99.0)], source_weights={"cpu.usage": {"a": 1, "b": 0}})
    )
    assert result["series"] == []
    assert len(result["weight_missing_windows"]) == 1


def test_disallowed_source_only_window_is_weight_missing():
    # Samples existed (so this is not the no-data case) but none came from an
    # allowed source.
    result = process(
        payload([sample(0, "zzz", 9.0)], source_weights={"cpu.usage": {"a": 1}})
    )
    assert result["series"] == []
    assert result["weight_missing_windows"] == [
        {"name": "cpu.usage", "labels": {"host": "db-1"}, "timestamp_ms": 0}
    ]


def test_window_without_any_sample_has_no_data_semantics():
    # One window has a weighted value; the neighbouring empty window neither
    # produces a row nor a weight-missing marker.
    result = process(
        payload([sample(1000, "a", 2.0)], source_weights=WEIGHTS)
    )
    assert [row["timestamp_ms"] for row in result["series"]] == [1000]
    assert result["weight_missing_windows"] == []


def test_cross_window_boundaries_align_independently():
    metrics = [
        sample(999, "a", 1.0),
        sample(1000, "b", 2.0),
        sample(1500, "a", 3.0),
    ]
    result = process(payload(metrics, source_weights=WEIGHTS))
    by_start = {row["timestamp_ms"]: row for row in result["series"]}
    assert sorted(by_start) == [0, 1000]
    assert by_start[0]["value"] == 1.0  # only a
    # window 1000: (3*1 + 2*3)/4 = 9/4
    assert by_start[1000]["value"] == 2.25
    assert by_start[1000]["sources"] == ["a", "b"]


def test_repeated_points_in_window_keep_dedup_semantics():
    # Identical point submitted twice: later value wins, counted once.
    result = process(
        payload(
            [sample(0, "a", 1.0), sample(0, "a", 2.0), sample(100, "b", 4.0)],
            source_weights=WEIGHTS,
        )
    )
    row = result["series"][0]
    # (2*1 + 4*3)/4 = 3.5
    assert row["value"] == 3.5
    assert row["count"] == 2


def test_same_source_multiple_points_all_count_in_window():
    result = process(
        payload(
            [
                sample(0, "a", 1.0),
                sample(500, "a", 3.0),
                sample(100, "b", 4.0),
            ],
            source_weights=WEIGHTS,
        )
    )
    # (1*1 + 3*1 + 4*3) / (1 + 1 + 3) = 16/5
    assert result["series"][0]["value"] == 3.2
    assert result["series"][0]["count"] == 3
    assert result["series"][0]["sources"] == ["a", "b"]


def test_labels_keep_separate_weighted_series():
    result = process(
        payload(
            [
                sample(0, "a", 1.0, labels={"host": "db-1"}),
                sample(0, "b", 5.0, labels={"host": "db-1"}),
                sample(0, "a", 9.0, labels={"host": "db-2"}),
            ],
            source_weights=WEIGHTS,
        )
    )
    rows = sorted(result["series"], key=lambda r: r["labels"]["host"])
    assert rows[0]["labels"]["host"] == "db-1" and rows[0]["value"] == 4.0
    assert rows[1]["labels"]["host"] == "db-2" and rows[1]["value"] == 9.0


def test_weighted_merge_coexists_with_source_quorum():
    # Quorum judged against participating sources including zero-weight.
    result = process(
        payload(
            [sample(0, "a", 6.0), sample(100, "b", 99.0)],
            source_weights={"cpu.usage": {"a": 1, "b": 0}},
            source_quorum={"cpu.usage": 2},
        )
    )
    assert len(result["series"]) == 1
    assert result["series"][0]["value"] == 6.0
    # Below quorum: window dropped (and is not reported as a value row).
    result_low = process(
        payload([sample(0, "a", 6.0)], source_weights=WEIGHTS, source_quorum={"cpu.usage": 2})
    )
    assert result_low["series"] == []


def test_alerts_unaffected_by_weighted_merge():
    alert = {
        "source": "a",
        "name": "cpu.usage",
        "labels": {"host": "db-1"},
        "alert_id": "a1",
        "rule": "cpu-high",
        "timestamp_ms": 0,
        "severity": "warning",
    }
    request = payload([sample(0, "a", 1.0), sample(100, "b", 5.0)], source_weights=WEIGHTS)
    request["alerts"] = [alert]
    result = process(request)
    assert result["alerts"] == [
        {"alert_id": "a1", "severity": "warning", "suppressed": False}
    ]
    assert result["suppressed_alert_ids"] == []


def test_weighted_value_rounds_and_normalizes_negative_zero():
    result = process(
        payload(
            [sample(0, "a", -0.0), sample(100, "b", 0.0)],
            source_weights=WEIGHTS,
        )
    )
    assert result["series"][0]["value"] == 0.0


# -- configuration validation ---------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "not-a-mapping",
        ["not-a-mapping"],
        {"": {"a": 1}},
        {"cpu.usage": {"a": -1}},
        {"cpu.usage": {"a": -0.01}},
        {"cpu.usage": {"a": float("nan")}},
        {"cpu.usage": {"a": float("inf")}},
        {"cpu.usage": {"a": -float("inf")}},
        {"cpu.usage": {"a": True}},
        {"cpu.usage": {"a": False}},
        {"cpu.usage": {"a": None}},
        {"cpu.usage": {"a": "1"}},
        {"cpu.usage": "nope"},
        {"cpu.usage": []},
        {"cpu.usage": {}},
        {"cpu.usage": ["x"]},
        {"cpu.usage": [{"source": "a"}]},
        {"cpu.usage": [{"weight": 1}]},
        {"cpu.usage": [{"source": "", "weight": 1}]},
        {"cpu.usage": [{"source": "a", "weight": -1}]},
        {"cpu.usage": [{"source": "a", "weight": float("nan")}]},
        # Duplicate source for the same target via the entry-list form.
        {"cpu.usage": [{"source": "a", "weight": 1}, {"source": "a", "weight": 2}]},
    ],
)
def test_invalid_source_weights_rejected_in_process(raw):
    with pytest.raises(SourceWeightError, match="^invalid source_weights$"):
        process(payload([sample(0, "a", 1.0)], source_weights=raw))


def test_zero_and_fractional_weights_are_valid():
    result = process(
        payload(
            [sample(0, "a", 2.0), sample(100, "b", 4.0)],
            source_weights={"cpu.usage": {"a": 0, "b": 0.25}},
        )
    )
    assert result["series"][0]["value"] == 4.0


def test_invalid_config_loads_no_partial_configuration():
    # The well-formed target must not be applied when a sibling target fails.
    raw = {"good": {"a": 1}, "bad": {"a": -1}}
    with pytest.raises(SourceWeightError):
        process(
            payload(
                [sample(0, "a", 1.0, name="good"), sample(100, "b", 9.0, name="good")],
                source_weights=raw,
            )
        )


def test_invalid_sample_rejected_without_touching_others():
    request = payload(
        [
            sample(0, "a", 1.0),
            {"source": "a", "name": "cpu.usage", "labels": {}, "timestamp_ms": 0,
             "value": float("nan")},
        ],
        source_weights=WEIGHTS,
    )
    with pytest.raises(ValueError, match="^invalid value$"):
        process(request)


# -- MetricBatchService ---------------------------------------------------------


def _service():
    return MetricBatchService(downsample_ms=1000, source_weights=WEIGHTS)


def test_service_weighted_query_and_missing_windows():
    service = _service()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "a", 2.0), sample(100, "b", 4.0)]}
    )
    rows = service.query_series()
    assert rows[0]["value"] == 3.5
    assert service.query_weight_missing_windows() == []

    # Window with only a disallowed source is weight-missing.
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 1900, "metrics": [sample(1000, "zz", 9.0)]}
    )
    missing = service.query_weight_missing_windows()
    assert [row["timestamp_ms"] for row in missing] == [1000]
    assert [row["timestamp_ms"] for row in service.query_series()] == [0]


def test_service_late_source_recomputes_weighted_window():
    service = _service()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a", 2.0)]}
    )
    assert service.query_series()[0]["value"] == 2.0
    # Late arrival of source b in the same window re-normalizes the result.
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900, "metrics": [sample(100, "b", 4.0)]}
    )
    assert service.query_series()[0]["value"] == 3.5


def test_service_zero_weight_window_then_positive_correction():
    service = MetricBatchService(
        downsample_ms=1000, source_weights={"cpu.usage": {"a": 0, "b": 1}}
    )
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a", 5.0)]}
    )
    assert service.query_series() == []
    assert len(service.query_weight_missing_windows()) == 1
    # A positive-weight source arriving late lifts the window out of missing.
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900, "metrics": [sample(100, "b", 8.0)]}
    )
    assert service.query_series()[0]["value"] == 8.0
    assert service.query_weight_missing_windows() == []


def test_service_retraction_recomputes_weighted_window_and_counts():
    service = _service()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a", 2.0)]}
    )
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900, "metrics": [sample(100, "b", 4.0)]}
    )
    assert service.query_series()[0]["value"] == 3.5
    result = service.retract_batch("b2")
    assert service.query_series()[0]["value"] == 2.0
    assert result["recomputed_windows"] == 1
    assert result["affected_streams"] == 1


def test_service_retraction_to_weight_missing_counts_as_changed():
    service = MetricBatchService(
        downsample_ms=1000, source_weights={"cpu.usage": {"a": 0, "b": 1}}
    )
    # The zero-weight source a is applied first; the positive-weight source b
    # arrives in a later (higher-rank) batch and lifts the window to a value.
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a", 5.0)]}
    )
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900, "metrics": [sample(100, "b", 8.0)]}
    )
    assert service.query_series()[0]["value"] == 8.0
    # Retracting b leaves only the zero-weight source: value window becomes
    # weight-missing (samples still exist, so it is not the no-data case).
    result = service.retract_batch("b2")
    assert service.query_series() == []
    missing = service.query_weight_missing_windows()
    assert [(row["name"], row["timestamp_ms"]) for row in missing] == [
        ("cpu.usage", 0)
    ]
    assert result["recomputed_windows"] == 1
    assert result["affected_streams"] == 1


def test_service_invalid_batch_rejected_leaving_state_intact():
    service = _service()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a", 2.0)]}
    )
    with pytest.raises(BatchError) as excinfo:
        service.apply_batch(
            {"batch_id": "bad", "max_event_time_ms": 2900,
             "metrics": [{"source": "b", "name": "cpu.usage", "labels": {},
                          "timestamp_ms": 2000, "value": math.inf}]}
        )
    assert excinfo.value.code == "metric_batch_invalid"
    # Previously accepted samples and queries are unaffected.
    assert len(service.query_series()) == 1
    assert service.query_series()[0]["value"] == 2.0


def test_service_constructor_rejects_invalid_weights():
    with pytest.raises(SourceWeightError, match="^invalid source_weights$"):
        MetricBatchService(downsample_ms=1000, source_weights={"x": {"a": -1}})


def test_service_set_source_weights_validates_all_or_nothing():
    service = _service()
    with pytest.raises(SourceWeightError):
        service.set_source_weights({"x": {"a": -1}})
    # Previous configuration survives the rejected replacement.
    assert service.source_weights == {"cpu.usage": {"a": 1, "b": 3}}


def test_service_set_source_weights_none_restores_equal_weight():
    service = _service()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "a", 2.0), sample(100, "b", 4.0)]}
    )
    assert service.query_series()[0]["value"] == 3.5
    service.set_source_weights(None)
    assert service.source_weights == {}
    # Equal-weight average restored and no missing markers remain.
    assert service.query_series()[0]["value"] == 3.0
    assert service.query_weight_missing_windows() == []


def test_service_enabling_weights_recomputes_existing_windows():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "a", 2.0), sample(100, "b", 4.0)]}
    )
    assert service.query_series()[0]["value"] == 3.0
    service.set_source_weights(WEIGHTS)
    assert service.query_series()[0]["value"] == 3.5


def test_service_reset_keeps_weight_configuration():
    service = _service()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a", 2.0)]}
    )
    service.reset()
    assert service.source_weights == {"cpu.usage": {"a": 1, "b": 3}}
    assert service.query_series() == []
    assert service.query_weight_missing_windows() == []


def test_service_weight_missing_filters_and_ordering():
    service = _service()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 2900,
         "metrics": [
             sample(2000, "zz", 1.0),
             sample(2500, "zz", 2.0, labels={"host": "other"}),
         ]}
    )
    missing = service.query_weight_missing_windows(
        name="cpu.usage", labels={"host": "db-1"}
    )
    assert [(row["timestamp_ms"], row["labels"]["host"]) for row in missing] == [
        (2000, "db-1")
    ]
    all_missing = service.query_weight_missing_windows(start_ms=2000)
    assert [row["timestamp_ms"] for row in all_missing] == [2000, 2000]
    assert service.query_weight_missing_windows(start_ms=2001) == []
