"""Tests for planned-maintenance windows (maintenance_windows)."""

import json
import subprocess
import sys

import pytest

from metric_fusion import (
    MaintenanceWindowError,
    MetricBatchService,
    process,
)


def make_window(**overrides):
    window = {
        "window_id": "w1",
        "start_ms": 100,
        "end_ms": 200,
        "source": "agent-a",
    }
    window.update(overrides)
    return window


def alert(alert_id, ts, source="agent-a", name="cpu.usage", labels=None, severity="warning", rule="cpu-high"):
    return {
        "source": source,
        "name": name,
        "labels": {"host": "db-1"} if labels is None else labels,
        "alert_id": alert_id,
        "rule": rule,
        "timestamp_ms": ts,
        "severity": severity,
    }


def sample(ts, source="agent-a", name="cpu.usage", labels=None, value=1.0):
    return {
        "source": source,
        "name": name,
        "labels": {"host": "db-1"} if labels is None else labels,
        "timestamp_ms": ts,
        "value": value,
    }


def request_payload(metrics, alerts, **extra):
    payload = {
        "downsample_ms": 1000,
        "suppression_ms": 0,
        "metrics": metrics,
        "alerts": alerts,
    }
    payload.update(extra)
    return payload


# -- configuration validation ------------------------------------------------


@pytest.mark.parametrize(
    "patch",
    [
        {"window_id": ""},
        {"window_id": 1},
        {"window_id": None},
        {"start_ms": -1},
        {"start_ms": "100"},
        {"start_ms": float("nan")},
        {"start_ms": float("inf")},
        {"start_ms": True},
        {"end_ms": -5},
        {"end_ms": 100},  # end must be greater than start
        {"end_ms": 50},
        {"end_ms": None},
        {"source": ""},
        {"source": 7},
        {"name": ""},
        {"labels": "nope"},
        {"labels": {"": "x"}},
        {"source": None, "name": None, "labels": None},  # no condition at all
    ],
)
def test_invalid_window_configurations(patch):
    payload = request_payload([], [], maintenance_windows=[make_window(**patch)])
    with pytest.raises(ValueError, match="invalid maintenance_window"):
        process(payload)


@pytest.mark.parametrize("raw", ["nope", 42, {"window_id": "w1"}, [make_window(), make_window()]])
def test_invalid_window_containers(raw):
    payload = request_payload([], [], maintenance_windows=raw)
    with pytest.raises(ValueError, match="invalid maintenance_window"):
        process(payload)


def test_window_without_any_condition_rejected():
    window = {"window_id": "w1", "start_ms": 0, "end_ms": 10}
    with pytest.raises(ValueError, match="invalid maintenance_window"):
        process(request_payload([], [], maintenance_windows=[window]))


def test_labels_only_and_name_only_windows_are_valid():
    result = process(
        request_payload(
            [],
            [alert("a1", 150), alert("a2", 150, name="mem.usage")],
            maintenance_windows=[
                {"window_id": "w1", "start_ms": 100, "end_ms": 200, "name": "cpu.usage"},
                {
                    "window_id": "w2",
                    "start_ms": 100,
                    "end_ms": 200,
                    "labels": {"host": "db-1"},
                },
            ],
        )
    )
    assert result["suppressed_alert_ids"] == ["a1", "a2"]


# -- matching semantics --------------------------------------------------------


def test_interval_is_half_open():
    windows = [make_window(start_ms=100, end_ms=200)]
    result = process(
        request_payload(
            [],
            [alert("a0", 99), alert("a1", 100), alert("a2", 199), alert("a3", 200)],
            maintenance_windows=windows,
        )
    )
    assert result["suppressed_alert_ids"] == ["a1", "a2"]
    by_id = {a["alert_id"]: a for a in result["alerts"]}
    assert by_id["a0"]["suppressed"] is False
    assert by_id["a3"]["suppressed"] is False


def test_all_provided_conditions_must_match():
    windows = [make_window(name="cpu.usage", labels={"host": "db-1"})]
    result = process(
        request_payload(
            [],
            [
                alert("a1", 150, rule="r1"),  # full match
                alert("a2", 150, source="agent-b", rule="r2"),  # source differs
                alert("a3", 150, name="mem.usage", rule="r3"),  # name differs
                alert("a4", 150, labels={"host": "db-2"}, rule="r4"),  # label differs
            ],
            maintenance_windows=windows,
        )
    )
    assert result["suppressed_alert_ids"] == ["a1"]


def test_labels_are_a_subset_condition():
    windows = [make_window(labels={"host": "db-1"})]
    result = process(
        request_payload(
            [],
            [alert("a1", 150, labels={"host": "db-1", "dc": "east"})],
            maintenance_windows=windows,
        )
    )
    assert result["suppressed_alert_ids"] == ["a1"]


def test_union_with_time_suppression_and_no_duplicate_ids():
    # a2 is suppressed by suppression_ms (same rule/name/labels as a1, within
    # the window, not higher severity); a3 only by the maintenance window.
    payload = request_payload(
        [],
        [alert("a1", 0), alert("a2", 10), alert("a3", 150)],
        maintenance_windows=[make_window()],
    )
    payload["suppression_ms"] = 50
    result = process(payload)
    assert result["suppressed_alert_ids"] == ["a2", "a3"]


def test_alert_fields_and_order_are_unchanged():
    alerts = [alert("a2", 150), alert("a1", 150)]
    result = process(
        request_payload([], alerts, maintenance_windows=[make_window()])
    )
    assert [a["alert_id"] for a in result["alerts"]] == ["a2", "a1"]
    assert set(result["alerts"][0]) == {"alert_id", "severity", "suppressed"}


def test_explanation_mode_uses_existing_status_expression():
    payload = request_payload(
        [],
        [alert("a1", 150)],
        maintenance_windows=[make_window()],
        enable_explanations=True,
        suppression_rules=[],
    )
    result = process(payload)
    assert result["alerts"][0]["status"] == "suppressed"
    assert result["suppressed_alert_ids"] == ["a1"]
    assert result["explanations"] == []  # no suppressor, no explanation record


def test_series_and_query_paths_ignore_maintenance_windows():
    payload = request_payload(
        [sample(150)],
        [alert("a1", 150)],
        maintenance_windows=[make_window()],
    )
    result = process(payload)
    assert len(result["series"]) == 1  # samples are never suppressed
    assert set(result) == {"series", "alerts", "suppressed_alert_ids"}


def test_absent_maintenance_windows_leaves_output_unchanged():
    payload = request_payload([sample(0)], [alert("a1", 10)])
    baseline = process(payload)
    assert set(baseline) == {"series", "alerts", "suppressed_alert_ids"}
    assert baseline["alerts"] == [
        {"alert_id": "a1", "severity": "warning", "suppressed": False}
    ]
    # Explicit null and empty list behave like "not provided".
    assert process(request_payload([sample(0)], [alert("a1", 10)], maintenance_windows=None)) == baseline
    assert process(request_payload([sample(0)], [alert("a1", 10)], maintenance_windows=[])) == baseline


# -- MetricBatchService --------------------------------------------------------


def test_service_constructor_and_setter():
    service = MetricBatchService(downsample_ms=1000, maintenance_windows=[make_window()])
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [], "alerts": [alert("a1", 150)]}
    )
    result = service.query_alerts()
    assert result["alerts"][0]["suppressed"] is True
    assert result["suppressed_alert_ids"] == ["a1"]

    # Full replacement: the old window no longer applies.
    service.set_maintenance_windows(
        [make_window(window_id="w2", start_ms=500, end_ms=600)]
    )
    assert service.query_alerts()["suppressed_alert_ids"] == []
    assert [w["window_id"] for w in service.maintenance_windows] == ["w2"]


def test_service_setter_is_all_or_nothing():
    service = MetricBatchService(downsample_ms=1000, maintenance_windows=[make_window()])
    with pytest.raises(MaintenanceWindowError):
        service.set_maintenance_windows([make_window(window_id="w2"), make_window(window_id="w2")])
    assert [w["window_id"] for w in service.maintenance_windows] == ["w1"]
    with pytest.raises(ValueError, match="invalid maintenance_window"):
        MetricBatchService(maintenance_windows=[make_window(end_ms=1)])


def test_service_reset_keeps_configuration():
    service = MetricBatchService(downsample_ms=1000, maintenance_windows=[make_window()])
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [], "alerts": [alert("a1", 150)]}
    )
    service.reset()
    assert service.query_alerts()["alerts"] == []
    assert [w["window_id"] for w in service.maintenance_windows] == ["w1"]
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900, "metrics": [], "alerts": [alert("a2", 150)]}
    )
    assert service.query_alerts()["suppressed_alert_ids"] == ["a2"]


def test_service_retraction_triggers_readjudication():
    service = MetricBatchService(downsample_ms=1000, maintenance_windows=[make_window()])
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [], "alerts": [alert("a1", 150)]}
    )
    assert service.query_alerts()["suppressed_alert_ids"] == ["a1"]
    service.retract_batch("b1")
    assert service.query_alerts()["suppressed_alert_ids"] == []
    # A late correction re-applying the alert is re-judged against the config.
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [], "alerts": [alert("a1", 150)]}
    )
    assert service.query_alerts()["suppressed_alert_ids"] == ["a1"]


def test_service_query_series_ignores_maintenance_windows():
    service = MetricBatchService(downsample_ms=1000, maintenance_windows=[make_window()])
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(150)]}
    )
    assert len(service.query_series()) == 1


# -- CLI -----------------------------------------------------------------------


def test_cli_invalid_maintenance_window_exits_2(tmp_path):
    payload = request_payload([], [], maintenance_windows=[make_window(end_ms=1)])
    request_file = tmp_path / "request.json"
    request_file.write_text(json.dumps(payload), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "invalid maintenance_window" in completed.stderr
