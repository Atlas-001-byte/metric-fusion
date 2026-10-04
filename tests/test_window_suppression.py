"""Tests for time-window suppression rules (source/label dimensional)."""

import pytest

from metric_fusion import (
    EventTimestampError,
    MetricBatchService,
    RuleConfigurationError,
    WindowSuppressionEngine,
    process,
    query_window_suppressions,
    reset_window_suppressions,
)


def make_rule(**overrides):
    rule = {
        "rule_id": "r1",
        "source": "agent-a",
        "metric": "cpu.*",
        "labels": {"host": "db-1"},
        "pending_ms": 100,
        "suppression_ms": 500,
        "recovery_ms": 200,
    }
    rule.update(overrides)
    return rule


def sample(ts, source="agent-a", name="cpu.usage", labels=None, value=1.0):
    return {
        "source": source,
        "name": name,
        "labels": {"host": "db-1"} if labels is None else labels,
        "timestamp_ms": ts,
        "value": value,
    }


def alert(alert_id, ts, source="agent-a", name="cpu.usage", labels=None, severity="warning"):
    return {
        "source": source,
        "name": name,
        "labels": {"host": "db-1"} if labels is None else labels,
        "alert_id": alert_id,
        "rule": "cpu-high",
        "timestamp_ms": ts,
        "severity": severity,
    }


@pytest.fixture(autouse=True)
def clean_default_engine():
    reset_window_suppressions()
    yield
    reset_window_suppressions()


# -- configuration validation ------------------------------------------------


@pytest.mark.parametrize(
    "patch",
    [
        {"source": ""},
        {"metric": ""},
        {"labels": {"": "x"}},
        {"labels": {"h": 1}},
        {"labels": "nope"},
        {"pending_ms": -1},
        {"suppression_ms": -5},
        {"recovery_ms": -2},
        {"pending_ms": 1.5},
        {"suppression_ms": None},
    ],
)
def test_invalid_rule_configurations(patch):
    engine = WindowSuppressionEngine()
    with pytest.raises(RuleConfigurationError):
        engine.set_rules([make_rule(**patch)])


def test_duplicate_rule_id_rejected():
    engine = WindowSuppressionEngine()
    with pytest.raises(RuleConfigurationError):
        engine.set_rules([make_rule(), make_rule()])


def test_set_rules_is_all_or_nothing():
    engine = WindowSuppressionEngine([make_rule()])
    with pytest.raises(RuleConfigurationError):
        engine.set_rules([make_rule(rule_id="r2"), make_rule(rule_id="r2")])
    assert [r["rule_id"] for r in engine.rules] == ["r1"]


def test_event_timestamp_errors():
    engine = WindowSuppressionEngine([make_rule()])
    with pytest.raises(RuleConfigurationError):
        engine.record_event({"source": "agent-a", "name": "cpu.usage", "labels": {}})
    with pytest.raises(RuleConfigurationError):
        engine.record_event(sample(None))
    for bad in ("soon", float("nan"), float("inf"), -1, True):
        with pytest.raises(EventTimestampError):
            engine.record_event(sample(bad))


# -- state machine -------------------------------------------------------------


def test_pending_accumulates_then_suppresses():
    engine = WindowSuppressionEngine([make_rule()])
    engine.record_event(sample(0))
    engine.record_event(sample(50))
    (state,) = engine.query(now_ms=50)
    assert state["status"] == "pending"
    assert state["active_start_ms"] == 0
    assert state["suppression_end_ms"] is None

    engine.record_event(sample(100))  # 100 - 0 >= pending_ms
    (state,) = engine.query(now_ms=100)
    assert state["status"] == "suppressed"
    assert state["active_start_ms"] == 0
    assert state["suppression_end_ms"] == 600


def test_suppression_window_does_not_extend():
    engine = WindowSuppressionEngine([make_rule()])
    for ts in (0, 100, 200, 400, 599):
        engine.record_event(sample(ts))
    (state,) = engine.query(now_ms=599)
    assert state["status"] == "suppressed"
    assert state["suppression_end_ms"] == 600


def test_recovery_observation_and_reset():
    engine = WindowSuppressionEngine([make_rule()])
    engine.record_event(sample(0))
    engine.record_event(sample(100))  # suppressed until 600, recovery until 800
    (state,) = engine.query(now_ms=650)
    assert state["status"] == "recovered"

    # A match during recovery restarts the observation; suppression end is kept.
    engine.record_event(sample(700))
    (state,) = engine.query(now_ms=850)
    assert state["status"] == "recovered"
    assert state["suppression_end_ms"] == 600
    (state,) = engine.query(now_ms=901)  # 700 + 200 recovery elapsed quietly
    assert state["status"] == "missed"
    assert state["suppression_end_ms"] == 600  # history remains queryable

    # After a quiet recovery the next match starts a fresh observation run.
    engine.record_event(sample(1000))
    (state,) = engine.query(now_ms=1000)
    assert state["status"] == "pending"
    assert state["active_start_ms"] == 1000


def test_zero_pending_suppresses_immediately():
    engine = WindowSuppressionEngine([make_rule(pending_ms=0)])
    engine.record_event(sample(10))
    (state,) = engine.query(now_ms=10)
    assert state["status"] == "suppressed"
    assert state["suppression_end_ms"] == 510


def test_label_combinations_are_independent():
    engine = WindowSuppressionEngine([make_rule(labels={})])
    engine.record_event(sample(0, labels={"host": "a"}))
    engine.record_event(sample(100, labels={"host": "a"}))
    engine.record_event(sample(100, labels={"host": "b"}))
    states = {tuple(sorted(s["labels"].items())): s for s in engine.query(now_ms=100)}
    assert states[(("host", "a"),)]["status"] == "suppressed"
    assert states[(("host", "b"),)]["status"] == "pending"


def test_duplicate_event_is_idempotent():
    engine = WindowSuppressionEngine([make_rule()])
    for _ in range(3):
        engine.record_event(sample(0))
        engine.record_event(sample(100))
    (state,) = engine.query(now_ms=100)
    assert state["status"] == "suppressed"
    assert state["suppression_end_ms"] == 600
    assert len(engine.query()) == 1


def test_multiple_rules_sorted_and_aggregate_follows_earliest_end():
    rules = [
        make_rule(rule_id="b-rule", pending_ms=0, suppression_ms=1000),
        make_rule(rule_id="a-rule", pending_ms=0, suppression_ms=100),
    ]
    engine = WindowSuppressionEngine(rules)
    engine.record_event(sample(0))
    states = engine.query(now_ms=0)
    assert [s["rule_id"] for s in states] == ["a-rule", "b-rule"]
    # Aggregate follows the earliest-ending window (a-rule ends at 100).
    assert engine.is_suppressed("agent-a", "cpu.usage", {"host": "db-1"}, 50)
    # a-rule's window (ending at 100) still governs during its recovery.
    assert not engine.is_suppressed("agent-a", "cpu.usage", {"host": "db-1"}, 150)
    # Once a-rule's episode is fully over, b-rule's live window governs.
    assert engine.is_suppressed("agent-a", "cpu.usage", {"host": "db-1"}, 500)


def test_config_change_is_not_retroactive_and_delete_keeps_history():
    engine = WindowSuppressionEngine([make_rule(pending_ms=0, suppression_ms=100)])
    engine.record_event(sample(0))  # suppressed until 100
    engine.set_rules([make_rule(pending_ms=0, suppression_ms=90000)])
    (state,) = engine.query(now_ms=0)
    assert state["suppression_end_ms"] == 100  # recorded hit unchanged

    engine.set_rules([])  # deletion stops future matching only
    engine.record_event(sample(200))
    states = engine.query(rule_id="r1", now_ms=200)
    assert len(states) == 1
    assert states[0]["status"] == "recovered"
    assert not engine.is_suppressed("agent-a", "cpu.usage", {"host": "db-1"}, 50)


# -- process() integration -----------------------------------------------------


def request_payload(metrics, alerts, **extra):
    payload = {
        "downsample_ms": 1000,
        "suppression_ms": 0,
        "metrics": metrics,
        "alerts": alerts,
    }
    payload.update(extra)
    return payload


def test_process_marks_alerts_and_exposes_states():
    rules = [make_rule(pending_ms=0, suppression_ms=500)]
    payload = request_payload(
        [sample(0)],
        [alert("a1", 10), alert("a2", 700)],
        window_suppression_rules=rules,
    )
    result = process(payload)
    by_id = {a["alert_id"]: a for a in result["alerts"]}
    assert by_id["a1"]["suppressed"] is True
    assert by_id["a2"]["suppressed"] is False
    assert result["suppressed_alert_ids"] == ["a1"]
    (state,) = result["suppression_states"]
    assert state["rule_id"] == "r1"
    assert state["source"] == "agent-a"
    assert state["labels"] == {"host": "db-1"}
    assert state["status"] == "recovered"  # now = last event time (700)
    # Cross-call query via the module-level default engine.
    assert query_window_suppressions(rule_id="r1", now_ms=10)[0]["status"] == "suppressed"


def test_process_without_window_rules_is_unchanged():
    payload = request_payload([sample(0)], [alert("a1", 10)])
    result = process(payload)
    assert set(result) == {"series", "alerts", "suppressed_alert_ids"}
    assert result["alerts"] == [
        {"alert_id": "a1", "severity": "warning", "suppressed": False}
    ]


def test_process_invalid_window_rules_raise_and_change_nothing():
    with pytest.raises(RuleConfigurationError):
        process(request_payload([sample(0)], [], window_suppression_rules=[make_rule(source="")]))
    assert query_window_suppressions() == []


def test_process_unmatched_data_flows_through():
    payload = request_payload(
        [sample(0, source="other")],
        [alert("a1", 10, source="other")],
        window_suppression_rules=[make_rule(pending_ms=0)],
    )
    result = process(payload)
    assert result["alerts"][0]["suppressed"] is False
    assert result["suppression_states"] == []
    assert len(result["series"]) == 1


# -- MetricBatchService integration --------------------------------------------


def test_service_tracks_states_across_batches():
    service = MetricBatchService(
        downsample_ms=1000, window_suppression_rules=[make_rule(pending_ms=100)]
    )
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0), sample(100)]}
    )
    (state,) = service.query_suppression_states()
    assert state["status"] == "suppressed"
    assert state["suppression_end_ms"] == 600

    # Idempotent replay of the same batch does not feed events again.
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0), sample(100)]}
    )
    assert len(service.query_suppression_states()) == 1

    service.apply_batch(
        {
            "batch_id": "b2",
            "max_event_time_ms": 1900,
            "metrics": [sample(1000)],
            "alerts": [alert("a1", 1000)],
        }
    )
    alerts = service.query_alerts()
    assert alerts["alerts"][0]["suppressed"] is False  # window ended at 600
    # The event at 1000 arrived after the recovery window (ends at 800) had
    # elapsed quietly, so it starts a fresh observation run.
    state = service.query_suppression_states(now_ms=1000)[0]
    assert state["status"] == "pending"
    assert state["active_start_ms"] == 1000


def test_service_alert_suppressed_inside_window():
    service = MetricBatchService(
        downsample_ms=1000, window_suppression_rules=[make_rule(pending_ms=0, suppression_ms=500)]
    )
    service.apply_batch({"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0)]})
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900, "metrics": [], "alerts": [alert("a1", 100)]}
    )
    result = service.query_alerts()
    assert result["alerts"][0]["suppressed"] is True
    assert result["suppressed_alert_ids"] == ["a1"]


def test_service_set_rules_and_reset():
    service = MetricBatchService(downsample_ms=1000)
    service.set_window_suppression_rules([make_rule(pending_ms=0)])
    service.apply_batch({"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0)]})
    assert service.query_suppression_states()[0]["status"] == "suppressed"
    service.reset()
    assert service.query_suppression_states() == []
    # Rules survive reset; new events match again.
    service.apply_batch({"batch_id": "b2", "max_event_time_ms": 900, "metrics": [sample(0)]})
    assert service.query_suppression_states()[0]["status"] == "suppressed"


def test_service_batch_level_rule_config():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0)],
            "window_suppression_rules": [make_rule(pending_ms=0)],
        }
    )
    assert service.query_suppression_states()[0]["status"] == "suppressed"
    with pytest.raises(RuleConfigurationError):
        service.apply_batch(
            {
                "batch_id": "b2",
                "max_event_time_ms": 900,
                "metrics": [],
                "window_suppression_rules": [make_rule(pending_ms=-1)],
            }
        )
