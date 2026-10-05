"""Tests for optional per-target source-priority failover (source_priority)."""

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


# -- process(): priority failover -----------------------------------------------


def test_priority_picks_first_configured_source_present():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(100, "b", value=2.0)],
            source_priority={"cpu.usage": ["a", "b"]},
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


def test_priority_fails_over_when_higher_source_absent():
    result = process(
        payload(
            [sample(0, "b", value=2.0), sample(100, "c", value=3.0)],
            source_priority={"cpu.usage": ["a", "b", "c"]},
        )
    )
    row = result["series"][0]
    assert row["value"] == 2.0
    assert row["sources"] == ["b"]
    assert row["count"] == 1


def test_priority_aggregates_all_samples_of_chosen_source():
    result = process(
        payload(
            [
                sample(0, "b", value=1.0),
                sample(100, "b", value=3.0),
                sample(50, "a", value=100.0),
            ],
            source_priority={"cpu.usage": ["b", "a"]},
        )
    )
    row = result["series"][0]
    assert row["value"] == 2.0
    assert row["count"] == 2
    assert row["sources"] == ["b"]


def test_unconfigured_targets_keep_existing_merge():
    metrics = [sample(0, "a", value=1.0), sample(100, "b", value=2.0)]
    baseline = process(payload(metrics))
    unmatched = process(payload(metrics, source_priority={"other": ["a"]}))
    assert baseline["series"] == unmatched["series"]
    assert baseline["series"][0]["value"] == 1.5
    assert set(unmatched) == {"series", "alerts", "suppressed_alert_ids"}


def test_priority_uses_aggregation_selection():
    metrics = [sample(0, "b", value=1.0), sample(100, "b", value=3.0)]
    for func, expected in [
        ("avg", 2.0),
        ("min", 1.0),
        ("max", 3.0),
        ("sum", 4.0),
        ("last", 3.0),
    ]:
        result = process(
            payload(
                metrics,
                aggregations={"cpu.usage": func},
                source_priority={"cpu.usage": ["b"]},
            )
        )
        assert result["series"][0]["value"] == expected


def test_priority_window_without_configured_sources_is_priority_missing():
    result = process(
        payload(
            [sample(0, "c", value=1.0)],
            source_priority={"cpu.usage": ["a", "b"]},
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


def test_normal_rows_do_not_carry_priority_missing():
    result = process(
        payload(
            [sample(0, "a", value=1.0)],
            source_priority={"cpu.usage": ["a"]},
        )
    )
    assert "priority_missing" not in result["series"][0]


def test_priority_window_without_any_samples_keeps_no_data_semantics():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(1000, "a", name="other", value=5.0)],
            source_priority={"cpu.usage": ["a"]},
        )
    )
    assert [(row["name"], row["timestamp_ms"]) for row in result["series"]] == [
        ("cpu.usage", 0),
        ("other", 1000),
    ]


def test_dedup_semantics_unchanged_for_priority_targets():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(0, "a", value=5.0)],
            source_priority={"cpu.usage": ["a"]},
        )
    )
    assert result["series"][0]["value"] == 5.0
    assert result["series"][0]["count"] == 1


def test_priority_selection_is_per_window():
    result = process(
        payload(
            [
                sample(0, "a", value=1.0),
                sample(100, "b", value=2.0),
                sample(1000, "b", value=4.0),
            ],
            source_priority={"cpu.usage": ["a", "b"]},
        )
    )
    assert [(row["timestamp_ms"], row["value"], row["sources"]) for row in result["series"]] == [
        (0, 1.0, ["a"]),
        (1000, 4.0, ["b"]),
    ]


def test_quorum_judged_on_full_source_set_before_selection():
    # Two sources deduplicated in the window: quorum 2 passes even though the
    # failover keeps only one of them.
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(50, "b", value=2.0)],
            source_quorum={"cpu.usage": 2},
            source_priority={"cpu.usage": ["a", "b"]},
        )
    )
    assert result["series"][0]["value"] == 1.0
    assert result["series"][0]["sources"] == ["a"]
    # Below the threshold the window is dropped entirely.
    result = process(
        payload(
            [sample(0, "a", value=1.0)],
            source_quorum={"cpu.usage": 2},
            source_priority={"cpu.usage": ["a", "b"]},
        )
    )
    assert result["series"] == []


def test_priority_value_rounding_and_negative_zero():
    result = process(
        payload(
            [sample(0, "a", value=1.0), sample(1, "a", value=2.0), sample(2, "a", value=2.0)],
            source_priority={"cpu.usage": ["a"]},
        )
    )
    assert result["series"][0]["value"] == round(5.0 / 3.0, 6)
    result = process(
        payload(
            [sample(0, "a", value=-0.0)],
            source_priority={"cpu.usage": ["a"]},
        )
    )
    assert result["series"][0]["value"] == 0.0


# -- configuration validation ---------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "not-a-mapping",
        ["a"],
        {},
        {"": ["a"]},
        {"cpu.usage": []},
        {"cpu.usage": "a"},
        {"cpu.usage": ["a", "a"]},
        {"cpu.usage": [""]},
        {"cpu.usage": [1]},
        {"cpu.usage": [None]},
        {"cpu.usage": [True]},
    ],
)
def test_invalid_source_priority_in_process(raw):
    with pytest.raises(ValueError, match="^invalid source_priority$"):
        process(payload([sample(0, "a")], source_priority=raw))


def test_source_priority_conflicts_with_source_weights_on_same_metric():
    with pytest.raises(ValueError, match="^invalid source_priority$"):
        process(
            payload(
                [sample(0, "a")],
                source_weights={"cpu.usage": {"a": 1.0}},
                source_priority={"cpu.usage": ["a"]},
            )
        )
    # Different metrics do not conflict.
    result = process(
        payload(
            [sample(0, "a"), sample(0, "b", name="mem.usage", value=2.0)],
            source_weights={"mem.usage": {"b": 1.0}},
            source_priority={"cpu.usage": ["a"]},
        )
    )
    assert len(result["series"]) == 2


def test_invalid_source_priority_is_all_or_nothing():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0, "a")]}
    )
    before = service.query_series()
    with pytest.raises(ValueError, match="^invalid source_priority$"):
        service.query_series(source_priority={"cpu.usage": []})
    assert service.query_series() == before


# -- MetricBatchService: queries, late data, retraction -------------------------


def test_service_priority_query_and_late_higher_priority_source():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(100, "b", value=2.0)]}
    )
    priority = {"cpu.usage": ["a", "b"]}
    rows = service.query_series(source_priority=priority)
    assert [(row["value"], row["sources"]) for row in rows] == [(2.0, ["b"])]

    # A late batch brings the higher-priority source into the same window;
    # subsequent queries fail over to it.
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900,
         "metrics": [sample(200, "a", value=1.0)]}
    )
    rows = service.query_series(source_priority=priority)
    assert [(row["value"], row["sources"]) for row in rows] == [(1.0, ["a"])]


def test_service_priority_recomputed_after_retraction():
    service = MetricBatchService(downsample_ms=1000)
    priority = {"cpu.usage": ["a", "b"]}
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "a", value=1.0)]}
    )
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900,
         "metrics": [sample(100, "b", value=3.0)]}
    )
    rows = service.query_series(source_priority=priority)
    assert rows[0]["value"] == 1.0

    # Retracting the higher-priority source's batch fails back to source b.
    service.retract_batch("b1")
    rows = service.query_series(source_priority=priority)
    assert rows[0]["value"] == 3.0
    assert rows[0]["sources"] == ["b"]


def test_service_priority_missing_and_recovery_via_late_batch():
    service = MetricBatchService(downsample_ms=1000)
    priority = {"cpu.usage": ["a"]}
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "c", value=7.0)]}
    )
    rows = service.query_series(source_priority=priority)
    assert rows[0]["value"] is None
    assert rows[0]["priority_missing"] is True
    assert rows[0]["count"] == 0
    assert rows[0]["sources"] == []

    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900,
         "metrics": [sample(100, "a", value=2.0)]}
    )
    rows = service.query_series(source_priority=priority)
    assert rows[0]["value"] == 2.0
    assert "priority_missing" not in rows[0]


def test_service_full_queries_and_defaults_ignore_priority():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, "a", value=1.0), sample(100, "b", value=2.0)]}
    )
    rows = service.query_series()
    assert rows[0]["value"] == 1.5
    assert set(rows[0]) == {"name", "labels", "timestamp_ms", "value", "count", "sources"}
    alerts = service.query_alerts()
    assert alerts["suppressed_alert_ids"] == []


def test_service_priority_query_filters_still_apply():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b0", "max_event_time_ms": 900,
         "metrics": [sample(0, "a", value=1.0)]}
    )
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 1900,
         "metrics": [
             sample(1000, "b", value=2.0),
             sample(1100, "a", name="other", value=9.0),
         ]}
    )
    priority = {"cpu.usage": ["a", "b"]}
    rows = service.query_series(name="cpu.usage", source_priority=priority)
    assert [(row["timestamp_ms"], row["value"]) for row in rows] == [(0, 1.0), (1000, 2.0)]
    rows = service.query_series(start_ms=1000, source_priority=priority)
    assert [(row["name"], row["timestamp_ms"]) for row in rows] == [
        ("cpu.usage", 1000),
        ("other", 1000),
    ]
