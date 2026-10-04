"""Tests for optional per-target source-weight merging (source_weights)."""

import pytest

from metric_fusion import BatchError, MetricBatchService, process


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


# -- process(): weighted merging ----------------------------------------------


def test_weighted_merge_basic_mapping_form():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(100, "b", value=2.0)],
            source_weights={"cpu.usage": {"a": 2.0, "b": 1.0}},
        )
    )
    assert result["series"] == [
        {
            "name": "cpu.usage",
            "labels": {"host": "db-1"},
            "timestamp_ms": 0,
            "value": round(4.0 / 3.0, 6),
            "count": 2,
            "sources": ["a", "b"],
        }
    ]


def test_weighted_merge_list_entry_form():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(100, "b", value=2.0)],
            source_weights={
                "cpu.usage": [
                    {"source": "a", "weight": 2.0},
                    {"source": "b", "weight": 1.0},
                ]
            },
        )
    )
    assert result["series"][0]["value"] == round(4.0 / 3.0, 6)


def test_unconfigured_targets_keep_equal_weight_default():
    metrics = [sample(0, "a", value=1.0), sample(100, "b", value=2.0)]
    baseline = process(payload(metrics))
    unmatched = process(payload(metrics, source_weights={"other": {"a": 5.0}}))
    assert baseline["series"] == unmatched["series"]
    assert baseline["series"][0]["value"] == 1.5
    assert set(unmatched) == {"series", "alerts", "suppressed_alert_ids"}


def test_partial_source_participation():
    # Only one configured source has samples in the window: it alone merges.
    result = process(
        payload(
            [sample(0, "a", value=3.0)],
            source_weights={"cpu.usage": {"a": 1.0, "b": 1.0}},
        )
    )
    assert result["series"][0]["value"] == 3.0
    assert result["series"][0]["sources"] == ["a"]


def test_unlisted_sources_do_not_participate():
    result = process(
        payload(
            [sample(0, "a", value=3.0), sample(50, "c", value=100.0)],
            source_weights={"cpu.usage": {"a": 1.0, "b": 1.0}},
        )
    )
    row = result["series"][0]
    assert row["value"] == 3.0
    assert row["sources"] == ["a"]
    assert row["count"] == 1


def test_multiple_samples_per_source_merge_per_sample():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "a", value=3.0),
                sample(50, "b", value=2.0),
            ],
            source_weights={"cpu.usage": {"a": 1.0, "b": 1.0}},
        )
    )
    assert result["series"][0]["value"] == 2.0
    assert result["series"][0]["count"] == 3


def test_zero_weight_counts_availability_but_not_value():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(50, "b", value=100.0)],
            source_weights={"cpu.usage": {"a": 2.0, "b": 0.0}},
        )
    )
    row = result["series"][0]
    assert row["value"] == 1.0
    assert row["sources"] == ["a", "b"]
    assert row["count"] == 2
    assert "weight_missing" not in row


def test_all_zero_weights_mark_window_weight_missing():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(50, "b", value=2.0)],
            source_weights={"cpu.usage": {"a": 0.0, "b": 0.0}},
        )
    )
    assert result["series"] == [
        {
            "name": "cpu.usage",
            "labels": {"host": "db-1"},
            "timestamp_ms": 0,
            "value": None,
            "count": 2,
            "sources": ["a", "b"],
            "weight_missing": True,
        }
    ]


def test_window_without_configured_sources_is_weight_missing():
    result = process(
        payload(
            [sample(0, "c", value=1.0)],
            source_weights={"cpu.usage": {"a": 1.0}},
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
            "weight_missing": True,
        }
    ]


def test_window_without_any_samples_keeps_no_data_semantics():
    # The weighted target has samples only in window 0; window 1000 belongs to
    # another metric, so no empty weighted window appears there.
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(1000, "a", name="other", value=5.0)],
            source_weights={"cpu.usage": {"a": 1.0}},
        )
    )
    assert [(row["name"], row["timestamp_ms"]) for row in result["series"]] == [
        ("cpu.usage", 0),
        ("other", 1000),
    ]


def test_dedup_semantics_unchanged_for_weighted_targets():
    # Identical points (source/name/labels/timestamp) dedupe, later wins.
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(0, "a", value=5.0)],
            source_weights={"cpu.usage": {"a": 1.0}},
        )
    )
    assert result["series"][0]["value"] == 5.0
    assert result["series"][0]["count"] == 1


def test_cross_window_boundaries():
    result = process(
        payload(
            [
                sample(999, "a", value=1.0),
                sample(1000, "a", value=2.0),
                sample(1000, "b", value=4.0),
            ],
            source_weights={"cpu.usage": {"a": 1.0, "b": 1.0}},
        )
    )
    assert [(row["timestamp_ms"], row["value"]) for row in result["series"]] == [
        (0, 1.0),
        (1000, 3.0),
    ]


def test_weighted_target_ignores_aggregation_selection():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(50, "b", value=2.0)],
            aggregations={"cpu.usage": "max"},
            source_weights={"cpu.usage": {"a": 1.0, "b": 1.0}},
        )
    )
    assert result["series"][0]["value"] == 1.5


def test_weighted_value_rounding_and_negative_zero():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(50, "b", value=2.0)],
            source_weights={"cpu.usage": {"a": 2.0, "b": 1.0}},
        )
    )
    assert result["series"][0]["value"] == round(4.0 / 3.0, 6)
    result = process(
        payload(
            [sample(0, "a", value=-0.0)],
            source_weights={"cpu.usage": {"a": 1.0}},
        )
    )
    assert result["series"][0]["value"] == 0.0


def test_quorum_still_filters_weighted_windows():
    result = process(
        payload(
            [sample(0, "a", value=1.0)],
            source_quorum={"cpu.usage": 2},
            source_weights={"cpu.usage": {"a": 1.0, "b": 1.0}},
        )
    )
    assert result["series"] == []


def test_alerts_unaffected_by_weight_missing_windows():
    alert = {
        "source": "a",
        "name": "cpu.usage",
        "labels": {"host": "db-1"},
        "alert_id": "a1",
        "rule": "cpu-high",
        "timestamp_ms": 0,
        "severity": "warning",
    }
    request = payload([sample(0, "c")], source_weights={"cpu.usage": {"a": 1.0}})
    request["alerts"] = [alert]
    result = process(request)
    assert result["series"][0]["weight_missing"] is True
    assert result["alerts"] == [
        {"alert_id": "a1", "severity": "warning", "suppressed": False}
    ]
    assert result["suppressed_alert_ids"] == []


# -- configuration validation ---------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "not-a-mapping",
        ["not-a-mapping"],
        {"": {"a": 1.0}},
        {"cpu.usage": {}},
        {"cpu.usage": []},
        {"cpu.usage": "x"},
        {"cpu.usage": {"a": -1}},
        {"cpu.usage": {"a": -0.5}},
        {"cpu.usage": {"a": float("inf")}},
        {"cpu.usage": {"a": float("nan")}},
        {"cpu.usage": {"a": True}},
        {"cpu.usage": {"a": False}},
        {"cpu.usage": {"a": "1"}},
        {"cpu.usage": {"": 1.0}},
        {"cpu.usage": [{"source": "a", "weight": 1.0}, {"source": "a", "weight": 2.0}]},
        {"cpu.usage": [{"source": "", "weight": 1.0}]},
        {"cpu.usage": [{"source": "a"}]},
        {"cpu.usage": [{"weight": 1.0}]},
        {"cpu.usage": [{"source": "a", "weight": -1}]},
        {"cpu.usage": ["a"]},
    ],
)
def test_invalid_source_weights_in_process(raw):
    with pytest.raises(ValueError, match="^invalid source_weights$"):
        process(payload([sample(0, "a")], source_weights=raw))


def test_invalid_source_weights_is_all_or_nothing():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a")]}
    )
    before = service.query_series()
    with pytest.raises(ValueError, match="^invalid source_weights$"):
        service.query_series(source_weights={"cpu.usage": {"a": -1}})
    assert service.query_series() == before


# -- sample validation ----------------------------------------------------------


@pytest.mark.parametrize(
    "bad_sample,message",
    [
        ({"name": "cpu.usage", "labels": {}, "timestamp_ms": 0, "value": 1.0}, "invalid metric"),
        ({"source": "a", "labels": {}, "timestamp_ms": 0, "value": 1.0}, "invalid metric"),
        ({"source": "a", "name": "cpu.usage", "labels": {}, "value": 1.0}, "invalid metric"),
        (
            {"source": "a", "name": "cpu.usage", "labels": {}, "timestamp_ms": 0,
             "value": float("nan")},
            "invalid value",
        ),
        (
            {"source": "a", "name": "cpu.usage", "labels": {}, "timestamp_ms": 0,
             "value": float("inf")},
            "invalid value",
        ),
    ],
)
def test_invalid_samples_rejected_with_weights_enabled(bad_sample, message):
    with pytest.raises(ValueError, match=f"^{message}$"):
        process(
            payload(
                [sample(0, "a"), bad_sample],
                source_weights={"cpu.usage": {"a": 1.0}},
            )
        )


def test_invalid_sample_leaves_accepted_state_untouched():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a", value=2.0)]}
    )
    before = service.query_series(source_weights={"cpu.usage": {"a": 1.0}})
    with pytest.raises(BatchError):
        service.apply_batch(
            {
                "batch_id": "b2",
                "max_event_time_ms": 900,
                "metrics": [
                    {"source": "a", "name": "cpu.usage", "labels": {"host": "db-1"},
                     "timestamp_ms": 100, "value": float("nan")}
                ],
            }
        )
    assert service.query_series(source_weights={"cpu.usage": {"a": 1.0}}) == before


# -- MetricBatchService: late data, correction, retraction ----------------------


def test_service_weighted_query_and_late_source():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(100, "a", value=1.0)]}
    )
    weights = {"cpu.usage": {"a": 1.0, "b": 1.0}}
    rows = service.query_series(source_weights=weights)
    assert [(row["timestamp_ms"], row["value"], row["sources"]) for row in rows] == [
        (0, 1.0, ["a"])
    ]

    # A late batch brings the second source into the same window; the window
    # is recomputed and subsequent queries return the corrected merge.
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900,
         "metrics": [sample(200, "b", value=3.0)]}
    )
    rows = service.query_series(source_weights=weights)
    assert [(row["timestamp_ms"], row["value"], row["sources"]) for row in rows] == [
        (0, 2.0, ["a", "b"])
    ]


def test_service_weighted_value_recomputed_after_retraction():
    service = MetricBatchService(downsample_ms=1000)
    weights = {"cpu.usage": {"a": 1.0, "b": 3.0}}
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "a", value=1.0)]}
    )
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900,
         "metrics": [sample(100, "b", value=3.0)]}
    )
    rows = service.query_series(source_weights=weights)
    assert rows[0]["value"] == round((1.0 + 9.0) / 4.0, 6)

    service.retract_batch("b2")
    rows = service.query_series(source_weights=weights)
    assert rows[0]["value"] == 1.0
    assert rows[0]["sources"] == ["a"]


def test_service_weight_missing_and_recovery_via_late_batch():
    service = MetricBatchService(downsample_ms=1000)
    weights = {"cpu.usage": {"a": 1.0}}
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "c", value=7.0)]}
    )
    rows = service.query_series(source_weights=weights)
    assert rows[0]["value"] is None
    assert rows[0]["weight_missing"] is True

    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900,
         "metrics": [sample(100, "a", value=2.0)]}
    )
    rows = service.query_series(source_weights=weights)
    assert rows[0]["value"] == 2.0
    assert "weight_missing" not in rows[0]


def test_service_full_queries_and_defaults_ignore_weights():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "a", value=1.0), sample(100, "b", value=2.0)]}
    )
    # Default query keeps the equal-weight avg and the existing row shape.
    rows = service.query_series()
    assert rows[0]["value"] == 1.5
    assert set(rows[0]) == {"name", "labels", "timestamp_ms", "value", "count", "sources"}
    alerts = service.query_alerts()
    assert alerts["suppressed_alert_ids"] == []
