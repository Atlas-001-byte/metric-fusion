"""Tests for explainable suppression (explain mode) and legacy compatibility."""

from __future__ import annotations

import pytest

from metric_fusion import ExplanationStore, alert_fingerprint, process


def _alert(alert_id, name="cpu.usage", labels=None, severity="warning", ts=1000):
    return {
        "source": "s1",
        "name": name,
        "labels": labels if labels is not None else {"host": "a"},
        "alert_id": alert_id,
        "rule": "r",
        "timestamp_ms": ts,
        "severity": severity,
    }


def _request(alerts, **extra):
    request = {
        "downsample_ms": 1000,
        "suppression_ms": 5000,
        "metrics": [],
        "alerts": alerts,
    }
    request.update(extra)
    return request


RULE = {
    "rule_id": "r1",
    "metric": "cpu.usage",
    "labels": {"host": "a"},
    "min_severity": "info",
    "duration_ms": 5000,
}


# --- legacy behavior unchanged when explain is off -------------------------


def test_legacy_mode_output_unchanged_shape():
    alerts = [_alert("a1", ts=1000), _alert("a2", ts=2000), _alert("a3", ts=9000)]
    result = process(_request(alerts))
    assert set(result) == {"series", "alerts", "suppressed_alert_ids"}
    assert result["alerts"] == [
        {"alert_id": "a1", "severity": "warning", "suppressed": False},
        {"alert_id": "a2", "severity": "warning", "suppressed": True},
        {"alert_id": "a3", "severity": "warning", "suppressed": False},
    ]
    assert result["suppressed_alert_ids"] == ["a2"]


def test_suppression_rules_ignored_when_explain_off():
    # Rules present but explain off: legacy suppression_ms logic still decides.
    alerts = [_alert("a1", ts=1000), _alert("a2", ts=2000)]
    result = process(_request(alerts, suppression_rules=[RULE]))
    assert "explanations" not in result
    assert result["suppressed_alert_ids"] == ["a2"]


# --- explain mode basics ---------------------------------------------------


def test_explain_mode_suppresses_and_records():
    alerts = [_alert("a1", ts=1000), _alert("a2", ts=2000)]
    result = process(_request(alerts, explain=True, suppression_rules=[RULE]))
    assert result["alerts"] == [
        {"alert_id": "a1", "severity": "warning", "suppressed": False},
        {"alert_id": "a2", "severity": "warning", "suppressed": True},
    ]
    fp = alert_fingerprint("cpu.usage", {"host": "a"})
    assert result["explanations"] == [
        {
            "suppressed_fingerprint": fp,
            "suppressor_fingerprint": fp,
            "rule_id": "r1",
            "started_at": 2000,
            "expires_at": 6000,
        }
    ]


def test_explain_mode_active_alert_has_no_record():
    alerts = [_alert("a1", ts=1000), _alert("a2", ts=9000)]
    result = process(_request(alerts, explain=True, suppression_rules=[RULE]))
    assert [a["suppressed"] for a in result["alerts"]] == [False, False]
    assert result["explanations"] == []


def test_explain_mode_no_matching_rule_stays_active():
    rule = dict(RULE, metric="other.metric")
    alerts = [_alert("a1", ts=1000), _alert("a2", ts=2000)]
    result = process(_request(alerts, explain=True, suppression_rules=[rule]))
    assert result["suppressed_alert_ids"] == []


def test_explain_mode_min_severity_filters():
    rule = dict(RULE, min_severity="critical")
    alerts = [_alert("a1", ts=1000), _alert("a2", ts=2000)]
    result = process(_request(alerts, explain=True, suppression_rules=[rule]))
    assert result["suppressed_alert_ids"] == []
    assert result["explanations"] == []


def test_explain_mode_cross_fingerprint_suppression():
    # A label-less rule matches both hosts; the first active alert suppresses
    # the other fingerprint within the window.
    rule = {"rule_id": "r1", "metric": "cpu.usage", "duration_ms": 5000}
    alerts = [
        _alert("a1", labels={"host": "a"}, ts=1000),
        _alert("a2", labels={"host": "b"}, ts=2000),
    ]
    result = process(_request(alerts, explain=True, suppression_rules=[rule]))
    assert result["suppressed_alert_ids"] == ["a2"]
    (record,) = result["explanations"]
    assert record["suppressed_fingerprint"] == alert_fingerprint(
        "cpu.usage", {"host": "b"}
    )
    assert record["suppressor_fingerprint"] == alert_fingerprint(
        "cpu.usage", {"host": "a"}
    )
    assert record["expires_at"] == 6000


def test_explain_mode_window_reanchors_on_active_alert():
    alerts = [
        _alert("a1", ts=1000),
        _alert("a2", ts=2000),   # suppressed by a1 (window 1000..6000)
        _alert("a3", ts=7000),   # outside a1's window -> active, new anchor
        _alert("a4", ts=8000),   # suppressed by a3 (window 7000..12000)
    ]
    result = process(_request(alerts, explain=True, suppression_rules=[RULE]))
    assert result["suppressed_alert_ids"] == ["a2", "a4"]
    assert [e["expires_at"] for e in result["explanations"]] == [6000, 12000]


def test_explain_mode_alert_output_order_and_fields_preserved():
    alerts = [_alert("a2", ts=2000), _alert("a1", ts=1000)]
    result = process(_request(alerts, explain=True, suppression_rules=[RULE]))
    # Output keeps input order even though processing sorts by time.
    assert [a["alert_id"] for a in result["alerts"]] == ["a2", "a1"]
    assert [a["suppressed"] for a in result["alerts"]] == [True, False]


# --- rule precedence -------------------------------------------------------


def test_rule_precedence_more_labels_wins():
    generic = {"rule_id": "a-generic", "metric": "cpu.usage", "duration_ms": 100}
    specific = dict(RULE, rule_id="z-specific", duration_ms=9000)
    alerts = [_alert("a1", ts=1000), _alert("a2", ts=2000)]
    result = process(
        _request(alerts, explain=True, suppression_rules=[generic, specific])
    )
    (record,) = result["explanations"]
    assert record["rule_id"] == "z-specific"
    assert record["expires_at"] == 1000 + 9000


def test_rule_precedence_exact_metric_beats_prefix():
    prefix = {
        "rule_id": "a-prefix",
        "metric_prefix": "cpu.",
        "duration_ms": 100,
    }
    exact = {"rule_id": "z-exact", "metric": "cpu.usage", "duration_ms": 9000}
    alerts = [_alert("a1", ts=1000), _alert("a2", ts=2000)]
    result = process(
        _request(alerts, explain=True, suppression_rules=[prefix, exact])
    )
    (record,) = result["explanations"]
    assert record["rule_id"] == "z-exact"


def test_rule_precedence_tie_breaks_on_rule_id():
    r1 = {"rule_id": "rule-b", "metric": "cpu.usage", "duration_ms": 100}
    r2 = {"rule_id": "rule-a", "metric": "cpu.usage", "duration_ms": 9000}
    alerts = [_alert("a1", ts=1000), _alert("a2", ts=2000)]
    result = process(_request(alerts, explain=True, suppression_rules=[r1, r2]))
    (record,) = result["explanations"]
    assert record["rule_id"] == "rule-a"
    assert record["expires_at"] == 1000 + 9000


# --- explanation store and queries -----------------------------------------


def test_store_query_by_fingerprint_and_rule_id():
    store = ExplanationStore()
    alerts = [_alert("a1", ts=1000), _alert("a2", ts=2000)]
    process(_request(alerts, explain=True, suppression_rules=[RULE]), store)
    fp = alert_fingerprint("cpu.usage", {"host": "a"})

    by_fp = store.query(fingerprint=fp, now_ms=3000)
    assert len(by_fp) == 1
    assert "ended_at" not in by_fp[0]  # still running: no guessed end

    ended = store.query(fingerprint=fp, now_ms=6000)
    assert ended[0]["ended_at"] == 6000  # known end, not a guess

    by_rule = store.query(rule_id="r1", now_ms=7000)
    assert by_rule[0]["ended_at"] == 6000

    assert store.query(fingerprint="no-such-fingerprint") == []
    assert store.query(rule_id="no-such-rule") == []


def test_store_accumulates_across_batches():
    store = ExplanationStore()
    process(
        _request(
            [_alert("a1", ts=1000), _alert("a2", ts=2000)],
            explain=True,
            suppression_rules=[RULE],
        ),
        store,
    )
    process(
        _request(
            [_alert("a3", ts=50000), _alert("a4", ts=51000)],
            explain=True,
            suppression_rules=[RULE],
        ),
        store,
    )
    records = store.query(rule_id="r1", now_ms=60000)
    assert len(records) == 2
    assert all(r["ended_at"] == r["expires_at"] for r in records)


def test_store_query_validates_argument_types():
    store = ExplanationStore()
    with pytest.raises(ValueError):
        store.query(fingerprint=123)
    with pytest.raises(ValueError):
        store.query(rule_id=5)
    with pytest.raises(ValueError):
        store.query(now_ms=float("nan"))
    with pytest.raises(ValueError):
        store.query(now_ms=-1)


# --- validation: ValueError and no partial output --------------------------


@pytest.mark.parametrize(
    "rule",
    [
        {},                                                     # missing rule_id
        {"rule_id": "", "duration_ms": 1},                      # empty rule_id
        {"rule_id": "r", "duration_ms": -1},                    # negative duration
        {"rule_id": "r"},                                       # missing duration
        {"rule_id": "r", "duration_ms": 1.5},                   # non-int duration
        {"rule_id": "r", "duration_ms": 1, "min_severity": "urgent"},
        {"rule_id": "r", "duration_ms": 1, "metric": 5},
        {"rule_id": "r", "duration_ms": 1, "metric_prefix": ""},
        {"rule_id": "r", "duration_ms": 1, "metric": "a", "metric_prefix": "a"},
        {"rule_id": "r", "duration_ms": 1, "labels": {"k": 1}},
        {"rule_id": "r", "duration_ms": 1, "labels": ["k"]},
    ],
)
def test_invalid_rules_raise_value_error(rule):
    request = _request([_alert("a1")], explain=True, suppression_rules=[rule])
    with pytest.raises(ValueError):
        process(request)


def test_duplicate_rule_id_raises():
    request = _request(
        [_alert("a1")], explain=True, suppression_rules=[RULE, dict(RULE)]
    )
    with pytest.raises(ValueError, match="duplicate rule_id"):
        process(request)


def test_invalid_explain_flag_raises():
    with pytest.raises(ValueError):
        process(_request([], explain="yes"))
    with pytest.raises(ValueError):
        process(_request([], explain=True, suppression_rules="not-a-list"))


def test_failed_validation_leaves_store_untouched():
    store = ExplanationStore()
    process(
        _request(
            [_alert("a1", ts=1000), _alert("a2", ts=2000)],
            explain=True,
            suppression_rules=[RULE],
        ),
        store,
    )
    bad = _request(
        [_alert("a3")],
        explain=True,
        suppression_rules=[{"rule_id": "r2", "duration_ms": -1}],
    )
    with pytest.raises(ValueError):
        process(bad, store)
    assert len(store.query()) == 1  # nothing partial was recorded


def test_explain_mode_still_validates_legacy_fields():
    with pytest.raises(ValueError, match="invalid downsample_ms"):
        process(_request([], explain=True, downsample_ms=0))
    with pytest.raises(ValueError, match="duplicate alert_id"):
        process(
            _request([_alert("a1"), _alert("a1")], explain=True,
                     suppression_rules=[RULE])
        )
