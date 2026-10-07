"""Tests for the suppression audit (include_suppression_audit / query_suppression_audit)."""

import json
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from urllib import error as urllib_error
from urllib import request as urllib_request

import pytest

from metric_fusion import (
    MetricBatchService,
    process,
    reset_explanations,
    reset_window_suppressions,
)


@pytest.fixture(autouse=True)
def clean_default_state():
    reset_window_suppressions()
    reset_explanations()
    yield
    reset_window_suppressions()
    reset_explanations()


# -- fixtures ----------------------------------------------------------------


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


def window(window_id="w1", start_ms=100, end_ms=200, **conditions):
    conditions.setdefault("source", "agent-a")
    return {
        "window_id": window_id,
        "start_ms": start_ms,
        "end_ms": end_ms,
        **conditions,
    }


def payload(alerts, metrics=None, suppression_ms=0, **extra):
    request = {
        "downsample_ms": 1000,
        "suppression_ms": suppression_ms,
        "metrics": [] if metrics is None else metrics,
        "alerts": alerts,
        "include_suppression_audit": True,
    }
    request.update(extra)
    return request


# -- basic shape -------------------------------------------------------------


def test_absent_flag_leaves_response_unchanged():
    result = process(
        {"downsample_ms": 1000, "suppression_ms": 0, "metrics": [], "alerts": [alert("a1", 100)]}
    )
    assert "suppression_audit" not in result
    assert set(result) == {"series", "alerts", "suppressed_alert_ids"}


def test_empty_audit_when_no_alerts():
    result = process(payload([]))
    assert result["suppression_audit"] == []


def test_one_record_per_alert_with_empty_causes_when_not_suppressed():
    alerts = [alert("a2", 200), alert("a1", 100)]
    result = process(payload(alerts))
    assert result["suppression_audit"] == [
        {"alert_id": "a2", "suppressed": False, "causes": []},
        {"alert_id": "a1", "suppressed": False, "causes": []},
    ]
    # Record order follows the alerts, not any internal ordering.
    assert [r["alert_id"] for r in result["suppression_audit"]] == ["a2", "a1"]


def test_record_fields_are_fixed():
    result = process(payload([alert("a1", 150)], maintenance_windows=[window()]))
    (record,) = result["suppression_audit"]
    assert set(record) == {"alert_id", "suppressed", "causes"}
    (cause,) = record["causes"]
    assert set(cause) == {"kind", "id"}


# -- time cause --------------------------------------------------------------


def test_time_suppression_cause():
    alerts = [alert("a1", 100), alert("a2", 150)]
    result = process(payload(alerts, suppression_ms=1000))
    by_id = {r["alert_id"]: r for r in result["suppression_audit"]}
    assert by_id["a1"] == {"alert_id": "a1", "suppressed": False, "causes": []}
    assert by_id["a2"] == {
        "alert_id": "a2",
        "suppressed": True,
        "causes": [{"kind": "time", "id": None}],
    }
    assert result["suppressed_alert_ids"] == ["a2"]


def test_higher_severity_breaks_time_suppression_without_cause():
    alerts = [
        alert("a1", 100, severity="warning"),
        alert("a2", 150, severity="critical"),
        alert("a3", 200, severity="critical"),
    ]
    result = process(payload(alerts, suppression_ms=1000))
    by_id = {r["alert_id"]: r for r in result["suppression_audit"]}
    assert by_id["a1"]["suppressed"] is False
    assert by_id["a2"]["suppressed"] is False
    assert by_id["a2"]["causes"] == []
    assert by_id["a3"]["suppressed"] is True
    assert by_id["a3"]["causes"] == [{"kind": "time", "id": None}]


# -- suppression_rule cause --------------------------------------------------


def test_suppression_rule_cause_only_when_explanations_enabled_and_rule_suppresses():
    rule = {
        "rule_id": "disk-flap",
        "selector": {"metric": "cpu.usage", "labels": {"host": "db-1"}},
        "min_severity": "info",
        "suppression_ms": 60000,
    }
    alerts = [alert("a1", 100), alert("a2", 200)]
    result = process(
        payload(
            alerts,
            enable_explanations=True,
            suppression_rules=[rule],
        )
    )
    by_id = {r["alert_id"]: r for r in result["suppression_audit"]}
    assert by_id["a1"] == {"alert_id": "a1", "suppressed": False, "causes": []}
    assert by_id["a2"] == {
        "alert_id": "a2",
        "suppressed": True,
        "causes": [{"kind": "suppression_rule", "id": "disk-flap"}],
    }


def test_no_suppression_rule_cause_when_explanations_disabled_even_with_rules():
    # Rules present in the payload are dormant without enable_explanations;
    # rule suppression therefore neither fires nor is audited.
    alerts = [alert("a1", 100), alert("a2", 200)]
    result = process(
        payload(
            alerts,
            suppression_rules=[
                {
                    "rule_id": "disk-flap",
                    "selector": {"metric": "cpu.usage"},
                    "min_severity": "info",
                    "suppression_ms": 60000,
                }
            ],
        )
    )
    assert all(
        not any(c["kind"] == "suppression_rule" for c in r["causes"])
        for r in result["suppression_audit"]
    )


def test_no_suppression_rule_cause_when_enabled_but_no_rule_suppresses():
    alerts = [alert("a1", 100), alert("a2", 200000)]
    result = process(
        payload(
            alerts,
            enable_explanations=True,
            suppression_rules=[
                {
                    "rule_id": "disk-flap",
                    "selector": {"metric": "cpu.usage"},
                    "min_severity": "info",
                    "suppression_ms": 60000,
                }
            ],
        )
    )
    by_id = {r["alert_id"]: r for r in result["suppression_audit"]}
    assert by_id["a2"]["suppressed"] is False
    assert by_id["a2"]["causes"] == []


def test_no_time_cause_in_explanation_mode_even_with_suppression_ms():
    # In explanation mode rule adjudication replaces baseline time suppression.
    alerts = [alert("a1", 100), alert("a2", 200)]
    result = process(
        payload(
            alerts,
            suppression_ms=100000,
            enable_explanations=True,
            suppression_rules=[],
        )
    )
    assert result["suppression_audit"] == [
        {"alert_id": "a1", "suppressed": False, "causes": []},
        {"alert_id": "a2", "suppressed": False, "causes": []},
    ]


# -- window_rule causes ------------------------------------------------------


def window_rule(rule_id="wr1", pending_ms=100, suppression_ms=500, recovery_ms=200, **overrides):
    rule = {
        "rule_id": rule_id,
        "source": "agent-a",
        "metric": "cpu.*",
        "labels": {"host": "db-1"},
        "pending_ms": pending_ms,
        "suppression_ms": suppression_ms,
        "recovery_ms": recovery_ms,
    }
    rule.update(overrides)
    return rule


def test_window_rule_cause():
    metrics = [sample(0), sample(100), sample(200)]
    alerts = [alert("a1", 250)]
    result = process(
        payload(alerts, metrics=metrics, window_suppression_rules=[window_rule()])
    )
    (record,) = result["suppression_audit"]
    assert record == {
        "alert_id": "a1",
        "suppressed": True,
        "causes": [{"kind": "window_rule", "id": "wr1"}],
    }


def test_multiple_window_rule_causes_sorted_and_deduped():
    rules = [
        window_rule("wr-b", metric="cpu.*"),
        window_rule("wr-a", metric="cpu.usage"),
    ]
    metrics = [sample(0), sample(100), sample(200)]
    alerts = [alert("a1", 250)]
    result = process(payload(alerts, metrics=metrics, window_suppression_rules=rules))
    (record,) = result["suppression_audit"]
    assert [c["id"] for c in record["causes"] if c["kind"] == "window_rule"] == [
        "wr-a",
        "wr-b",
    ]


# -- maintenance causes ------------------------------------------------------


def test_maintenance_cause():
    result = process(payload([alert("a1", 150)], maintenance_windows=[window()]))
    assert result["suppression_audit"] == [
        {
            "alert_id": "a1",
            "suppressed": True,
            "causes": [{"kind": "maintenance", "id": "w1"}],
        }
    ]


def test_multiple_maintenance_causes_sorted_and_deduped():
    windows = [
        window("w-b", name="cpu.usage"),
        window("w-a", source=None, name="cpu.usage"),
    ]
    result = process(payload([alert("a1", 150)], maintenance_windows=windows))
    (record,) = result["suppression_audit"]
    assert [c["id"] for c in record["causes"] if c["kind"] == "maintenance"] == [
        "w-a",
        "w-b",
    ]


def test_alert_outside_maintenance_window_has_no_cause():
    result = process(payload([alert("a1", 250)], maintenance_windows=[window(end_ms=200)]))
    assert result["suppression_audit"] == [
        {"alert_id": "a1", "suppressed": False, "causes": []}
    ]


# -- ordering across kinds ---------------------------------------------------


def test_cause_kind_ordering():
    # time + window_rule + maintenance together (no explanations), kinds must
    # be ordered: time, (suppression_rule), window_rule, maintenance.
    rules = [window_rule()]
    metrics = [sample(0), sample(100), sample(200)]
    alerts = [alert("a1", 50), alert("a2", 250)]
    result = process(
        payload(
            alerts,
            metrics=metrics,
            suppression_ms=100000,
            window_suppression_rules=rules,
            maintenance_windows=[window("wm1", start_ms=0, end_ms=1000)],
        )
    )
    by_id = {r["alert_id"]: r for r in result["suppression_audit"]}
    # a1 arrives during the pending phase: not window-suppressed yet.
    assert by_id["a1"]["causes"] == [{"kind": "maintenance", "id": "wm1"}]
    kinds = [c["kind"] for c in by_id["a2"]["causes"]]
    assert kinds == ["time", "window_rule", "maintenance"]
    # ids carry through per kind
    causes = {(c["kind"], c["id"]) for c in by_id["a2"]["causes"]}
    assert ("time", None) in causes
    assert ("window_rule", "wr1") in causes
    assert ("maintenance", "wm1") in causes


def test_full_kind_ordering_with_explanations():
    # rule + window + maintenance at once
    rule = {
        "rule_id": "sr1",
        "selector": {"metric": "cpu.usage"},
        "min_severity": "info",
        "suppression_ms": 60000,
    }
    metrics = [sample(0), sample(100), sample(200)]
    alerts = [alert("a1", 50), alert("a2", 250)]
    result = process(
        payload(
            alerts,
            metrics=metrics,
            enable_explanations=True,
            suppression_rules=[rule],
            window_suppression_rules=[window_rule()],
            maintenance_windows=[window("wm1", start_ms=0, end_ms=1000)],
        )
    )
    by_id = {r["alert_id"]: r for r in result["suppression_audit"]}
    # a1 only falls in the maintenance window; a2 carries the other three.
    assert by_id["a1"]["causes"] == [{"kind": "maintenance", "id": "wm1"}]
    kinds = [c["kind"] for c in by_id["a2"]["causes"]]
    assert kinds == ["suppression_rule", "window_rule", "maintenance"]


# -- flag validation ---------------------------------------------------------


@pytest.mark.parametrize("value", ["true", "false", 1, 0, None, [], {}])
def test_invalid_include_flag_raises(value):
    with pytest.raises(ValueError, match="^invalid suppression audit$"):
        process(
            {
                "downsample_ms": 1000,
                "suppression_ms": 0,
                "metrics": [],
                "alerts": [],
                "include_suppression_audit": value,
            }
        )


def test_failed_request_produces_no_partial_audit():
    with pytest.raises(ValueError):
        process(
            {
                "downsample_ms": 1000,
                "suppression_ms": 0,
                "metrics": [],
                "alerts": [],
                "include_suppression_audit": "yes",
                "maintenance_windows": [{}],
            }
        )


def test_audit_does_not_affect_other_response_fields():
    alerts = [alert("a1", 100), alert("a2", 200)]
    base_kwargs = dict(
        downsample_ms=1000,
        suppression_ms=1000,
        metrics=[sample(100)],
        alerts=alerts,
        maintenance_windows=[window("wm1", start_ms=0, end_ms=1000)],
    )
    without = process(dict(base_kwargs))
    with_audit = process(dict(base_kwargs, include_suppression_audit=True))
    for key in ("series", "alerts", "suppressed_alert_ids"):
        assert without[key] == with_audit[key]
    assert set(with_audit) - set(without) == {"suppression_audit"}


# -- stateful service --------------------------------------------------------


def test_service_query_suppression_audit_reflects_patches():
    service = MetricBatchService(
        downsample_ms=1000,
        suppression_ms=100000,
        maintenance_windows=[window("wm1", start_ms=0, end_ms=1000)],
    )
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 300,
            "metrics": [sample(0), sample(100), sample(200)],
            "alerts": [alert("a1", 100), alert("a2", 250)],
        }
    )
    audit = service.query_suppression_audit()
    by_id = {r["alert_id"]: r for r in audit}
    assert by_id["a1"]["causes"] == [{"kind": "maintenance", "id": "wm1"}]
    assert [c["kind"] for c in by_id["a2"]["causes"]] == ["time", "maintenance"]

    # Late correction: replace the batch with alerts outside the window and
    # far enough apart that time suppression no longer applies.
    service.retract_batch("b1")
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 600000,
            "metrics": [],
            "alerts": [alert("a1", 400000), alert("a2", 600000)],
        }
    )
    audit = service.query_suppression_audit()
    assert audit == [
        {"alert_id": "a1", "suppressed": False, "causes": []},
        {"alert_id": "a2", "suppressed": False, "causes": []},
    ]


def test_service_audit_reflects_retraction_of_suppressor():
    service = MetricBatchService(downsample_ms=1000, suppression_ms=100000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 200,
            "metrics": [],
            "alerts": [alert("a1", 100), alert("a2", 200)],
        }
    )
    assert service.query_suppression_audit()[1]["suppressed"] is True
    service.retract_batch("b1")
    assert service.query_suppression_audit() == []
    # Only the remaining (none here) alerts are adjudicated.
    service.apply_batch(
        {
            "batch_id": "b2",
            "max_event_time_ms": 200,
            "metrics": [],
            "alerts": [alert("a2", 200)],
        }
    )
    assert service.query_suppression_audit() == [
        {"alert_id": "a2", "suppressed": False, "causes": []}
    ]


def test_service_idempotent_apply_and_retract_do_not_duplicate_records():
    service = MetricBatchService(
        downsample_ms=1000,
        suppression_ms=100000,
        window_suppression_rules=[window_rule()],
    )
    request = {
        "batch_id": "b1",
        "max_event_time_ms": 250,
        "metrics": [sample(0), sample(100), sample(200)],
        "alerts": [alert("a1", 250)],
    }
    service.apply_batch(request)
    service.apply_batch(json.loads(json.dumps(request)))  # identical duplicate
    audit = service.query_suppression_audit()
    assert [r["alert_id"] for r in audit] == ["a1"]
    service.retract_batch("b1")
    service.retract_batch("b1")  # idempotent no-op
    audit = service.query_suppression_audit()
    assert audit == []


def test_service_audit_matches_query_alerts_verdicts():
    service = MetricBatchService(
        downsample_ms=1000,
        suppression_ms=100000,
        maintenance_windows=[window("wm1", start_ms=0, end_ms=1000)],
    )
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 300,
            "metrics": [],
            "alerts": [
                alert("a1", 100),
                alert("a2", 200),
                alert("a3", 3000),
            ],
        }
    )
    verdicts = {a["alert_id"]: a["suppressed"] for a in service.query_alerts()["alerts"]}
    audit = service.query_suppression_audit()
    assert {r["alert_id"]: r["suppressed"] for r in audit} == verdicts
    # suppressed records always carry at least one cause; active ones never do.
    for record in audit:
        assert record["suppressed"] == (len(record["causes"]) > 0)


def test_service_audit_with_explanations_lists_rule_causes():
    service = MetricBatchService(
        downsample_ms=1000,
        enable_explanations=True,
        suppression_rules=[
            {
                "rule_id": "sr1",
                "selector": {"metric": "cpu.usage"},
                "min_severity": "info",
                "suppression_ms": 60000,
            }
        ],
    )
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 300,
            "metrics": [],
            "alerts": [alert("a1", 100), alert("a2", 200)],
        }
    )
    by_id = {r["alert_id"]: r for r in service.query_suppression_audit()}
    assert by_id["a2"]["causes"] == [{"kind": "suppression_rule", "id": "sr1"}]


def test_service_window_rule_cause_after_late_events():
    service = MetricBatchService(
        downsample_ms=1000, window_suppression_rules=[window_rule()]
    )
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 200,
            "metrics": [sample(0), sample(100), sample(200)],
            "alerts": [],
        }
    )
    # A late alert is adjudicated against the accumulated window state.
    service.apply_batch(
        {
            "batch_id": "b2",
            "max_event_time_ms": 250,
            "metrics": [],
            "alerts": [alert("a1", 250)],
        }
    )
    assert service.query_suppression_audit() == [
        {
            "alert_id": "a1",
            "suppressed": True,
            "causes": [{"kind": "window_rule", "id": "wr1"}],
        }
    ]


def test_service_audit_query_is_read_only():
    service = MetricBatchService(
        downsample_ms=1000,
        enable_explanations=True,
        suppression_rules=[
            {
                "rule_id": "sr1",
                "selector": {"metric": "cpu.usage"},
                "min_severity": "info",
                "suppression_ms": 60000,
            }
        ],
    )
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 200,
            "metrics": [],
            "alerts": [alert("a1", 100), alert("a2", 200)],
        }
    )
    service.query_suppression_audit()
    service.query_suppression_audit()
    from metric_fusion import query_explanations

    # The audit path must not commit explanation records.
    assert query_explanations() == []


# -- CLI ---------------------------------------------------------------------


def test_cli_invalid_flag_exits_2(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(
            {
                "downsample_ms": 1000,
                "suppression_ms": 0,
                "metrics": [],
                "alerts": [],
                "include_suppression_audit": "true",
            }
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert completed.stderr.strip().endswith("invalid suppression audit")
    assert completed.stdout == ""


def test_cli_outputs_audit(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(
            payload(
                [alert("a1", 150)],
                maintenance_windows=[window()],
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
    out = json.loads(completed.stdout)
    assert out["suppression_audit"][0]["causes"] == [
        {"kind": "maintenance", "id": "w1"}
    ]


# -- HTTP --------------------------------------------------------------------


@pytest.fixture
def http_service():
    from metric_fusion.server import _make_handler

    service = MetricBatchService(downsample_ms=1000, suppression_ms=100000)
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
        try:
            with urllib_request.urlopen(base + path) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib_error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    yield service, post, get
    server.shutdown()
    server.server_close()
    thread.join()


def test_http_process_invalid_flag_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/process",
        {
            "downsample_ms": 1000,
            "suppression_ms": 0,
            "metrics": [],
            "alerts": [],
            "include_suppression_audit": "true",
        },
    )
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid suppression audit"}


def test_http_get_suppression_audit(http_service):
    service, post, get = http_service
    post(
        "/v1/metric_batches",
        {
            "batch_id": "b1",
            "max_event_time_ms": 200,
            "metrics": [],
            "alerts": [alert("a1", 100), alert("a2", 200)],
        },
    )
    status, body = get("/v1/suppression_audit")
    assert status == 200
    assert set(body) == {"suppression_audit"}
    by_id = {r["alert_id"]: r for r in body["suppression_audit"]}
    assert by_id["a1"]["suppressed"] is False
    assert by_id["a2"] == {
        "alert_id": "a2",
        "suppressed": True,
        "causes": [{"kind": "time", "id": None}],
    }


def test_http_get_suppression_audit_does_not_change_other_state(http_service):
    service, post, get = http_service
    post(
        "/v1/metric_batches",
        {
            "batch_id": "b1",
            "max_event_time_ms": 200,
            "metrics": [sample(100)],
            "alerts": [alert("a1", 100), alert("a2", 200)],
        },
    )
    get("/v1/suppression_audit")
    get("/v1/suppression_audit")
    _status1, alerts1 = get("/v1/alerts")
    _status2, alerts2 = get("/v1/alerts")
    assert alerts1 == alerts2
    _s1, series1 = get("/v1/series")
    _s2, series2 = get("/v1/series")
    assert series1 == series2
    assert len(series1["series"]) == 1
