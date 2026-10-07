"""Tests for the suppression audit (include_suppression_audit)."""

import json
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from urllib import error as urllib_error
from urllib import request as urllib_request

import pytest

from metric_fusion import MetricBatchService, process
from metric_fusion.server import _make_handler


# -- fixtures / builders ------------------------------------------------------


def sample(ts, source="agent-a", name="cpu.usage", labels=None, value=1.0):
    return {
        "source": source,
        "name": name,
        "labels": {} if labels is None else labels,
        "timestamp_ms": ts,
        "value": value,
    }


def alert(
    alert_id,
    ts,
    source="agent-a",
    name="cpu.usage",
    labels=None,
    severity="warning",
    rule="cpu-high",
):
    return {
        "source": source,
        "name": name,
        "labels": {} if labels is None else labels,
        "alert_id": alert_id,
        "rule": rule,
        "timestamp_ms": ts,
        "severity": severity,
    }


def window_rule(rule_id="w1", **overrides):
    rule = {
        "rule_id": rule_id,
        "source": "agent-a",
        "metric": "cpu.usage",
        "labels": {},
        "pending_ms": 0,
        "suppression_ms": 100000,
        "recovery_ms": 0,
    }
    rule.update(overrides)
    return rule


def maintenance_window(window_id="m1", **overrides):
    window = {
        "window_id": window_id,
        "start_ms": 0,
        "end_ms": 100000,
        "source": "agent-a",
    }
    window.update(overrides)
    return window


def suppression_rule(rule_id="r1", duration=100000):
    return {
        "rule_id": rule_id,
        "selector": {"metric": "cpu.usage"},
        "min_severity": "info",
        "suppression_ms": duration,
    }


def payload(metrics, alerts, **extra):
    request = {
        "downsample_ms": 1000,
        "suppression_ms": 0,
        "metrics": metrics,
        "alerts": alerts,
    }
    request.update(extra)
    return request


# -- stateless process(): shape and defaults ---------------------------------


def test_audit_absent_by_default_and_when_false():
    request = payload([sample(0)], [alert("a1", 10)], maintenance_windows=[maintenance_window()])
    assert "suppression_audit" not in process(request)
    assert "suppression_audit" not in process({**request, "include_suppression_audit": False})


def test_audit_one_record_per_alert_in_input_order():
    alerts = [alert("a2", 10), alert("a1", 20, severity="critical")]
    result = process(
        payload([sample(0)], alerts, include_suppression_audit=True, suppression_ms=50)
    )
    audit = result["suppression_audit"]
    assert [record["alert_id"] for record in audit] == ["a2", "a1"]
    assert [set(record) for record in audit] == [
        {"alert_id", "suppressed", "causes"},
        {"alert_id", "suppressed", "causes"},
    ]
    # The higher-severity alert breaks through; neither is suppressed here.
    assert audit == [
        {"alert_id": "a2", "suppressed": False, "causes": []},
        {"alert_id": "a1", "suppressed": False, "causes": []},
    ]


def test_audit_matches_suppressed_alert_ids():
    result = process(
        payload(
            [sample(0)],
            [alert("a1", 10), alert("a2", 20), alert("a3", 30)],
            include_suppression_audit=True,
            suppression_ms=100,
        )
    )
    audit = result["suppression_audit"]
    assert [r["alert_id"] for r in audit if r["suppressed"]] == result["suppressed_alert_ids"]
    assert audit[0]["suppressed"] is False and audit[0]["causes"] == []
    assert all(record["causes"] for record in audit[1:])


# -- individual cause kinds ---------------------------------------------------


def test_time_cause_only_in_baseline_mode():
    result = process(
        payload(
            [],
            [alert("a1", 0), alert("a2", 50)],
            include_suppression_audit=True,
            suppression_ms=100,
        )
    )
    assert result["suppression_audit"] == [
        {"alert_id": "a1", "suppressed": False, "causes": []},
        {"alert_id": "a2", "suppressed": True, "causes": [{"kind": "time", "id": None}]},
    ]


def test_no_time_cause_in_explanation_mode():
    result = process(
        payload(
            [],
            [alert("a1", 0), alert("a2", 50)],
            include_suppression_audit=True,
            suppression_ms=100,
            enable_explanations=True,
            suppression_rules=[suppression_rule()],
        )
    )
    causes = result["suppression_audit"][1]["causes"]
    assert [c["kind"] for c in causes] == ["suppression_rule"]
    assert causes == [{"kind": "suppression_rule", "id": "r1"}]


def test_suppression_rule_cause_requires_enabled_explanations():
    # Dormant rules never produce suppression_rule causes even with audit on.
    result = process(
        payload(
            [],
            [alert("a1", 0), alert("a2", 50)],
            include_suppression_audit=True,
            suppression_ms=100,
            suppression_rules=[suppression_rule()],
        )
    )
    kinds = {c["kind"] for c in result["suppression_audit"][1]["causes"]}
    assert "suppression_rule" not in kinds


def test_window_rule_causes_list_every_hit_sorted():
    result = process(
        payload(
            [sample(0)],
            [alert("a1", 10)],
            include_suppression_audit=True,
            window_suppression_rules=[
                window_rule("z-rule"),
                window_rule("a-rule"),
            ],
        )
    )
    causes = result["suppression_audit"][0]["causes"]
    assert causes == [
        {"kind": "window_rule", "id": "a-rule"},
        {"kind": "window_rule", "id": "z-rule"},
    ]


def test_maintenance_causes_list_every_hit_sorted():
    result = process(
        payload(
            [],
            [alert("a1", 10)],
            include_suppression_audit=True,
            maintenance_windows=[
                maintenance_window("m2"),
                maintenance_window("m1"),
            ],
        )
    )
    causes = result["suppression_audit"][0]["causes"]
    assert causes == [
        {"kind": "maintenance", "id": "m1"},
        {"kind": "maintenance", "id": "m2"},
    ]


def test_all_four_causes_are_merged_in_fixed_order():
    result = process(
        payload(
            [sample(0)],
            [alert("a1", 0), alert("a2", 50)],
            include_suppression_audit=True,
            suppression_ms=100,
            enable_explanations=True,
            suppression_rules=[suppression_rule("r-rule")],
            window_suppression_rules=[window_rule("z-rule"), window_rule("a-rule")],
            maintenance_windows=[maintenance_window("m2"), maintenance_window("m1")],
        )
    )
    first, second = result["suppression_audit"]
    # The anchor itself is not rule-suppressed, but window/maintenance hit.
    assert first["causes"] == [
        {"kind": "window_rule", "id": "a-rule"},
        {"kind": "window_rule", "id": "z-rule"},
        {"kind": "maintenance", "id": "m1"},
        {"kind": "maintenance", "id": "m2"},
    ]
    assert second["causes"] == [
        {"kind": "suppression_rule", "id": "r-rule"},
        {"kind": "window_rule", "id": "a-rule"},
        {"kind": "window_rule", "id": "z-rule"},
        {"kind": "maintenance", "id": "m1"},
        {"kind": "maintenance", "id": "m2"},
    ]


def test_time_window_maintenance_order_without_explanations():
    result = process(
        payload(
            [sample(0)],
            [alert("a1", 0), alert("a2", 50)],
            include_suppression_audit=True,
            suppression_ms=100,
            window_suppression_rules=[window_rule()],
            maintenance_windows=[maintenance_window()],
        )
    )
    assert result["suppression_audit"][1]["causes"] == [
        {"kind": "time", "id": None},
        {"kind": "window_rule", "id": "w1"},
        {"kind": "maintenance", "id": "m1"},
    ]


def test_unsuppressed_alert_never_lists_causes_even_when_others_match():
    # The triggering observation stays emitted while the rule accumulates.
    result = process(
        payload(
            [sample(0)],
            [alert("a1", 10, source="agent-b")],
            include_suppression_audit=True,
            window_suppression_rules=[window_rule()],
            maintenance_windows=[maintenance_window()],
        )
    )
    assert result["suppression_audit"] == [
        {"alert_id": "a1", "suppressed": False, "causes": []}
    ]


# -- validation / all-or-nothing ---------------------------------------------


@pytest.mark.parametrize("bad", ["true", "false", 1, 0, None, [], {}])
def test_invalid_include_flag_raises(bad):
    with pytest.raises(ValueError, match="invalid suppression audit"):
        process(payload([], [], include_suppression_audit=bad))


def test_invalid_flag_with_otherwise_valid_audit_inputs_changes_nothing():
    from metric_fusion import query_window_suppressions, reset_window_suppressions

    reset_window_suppressions()
    with pytest.raises(ValueError, match="invalid suppression audit"):
        process(
            payload(
                [sample(0)],
                [alert("a1", 10)],
                include_suppression_audit="yes",
                window_suppression_rules=[window_rule()],
            )
        )
    assert query_window_suppressions() == []


def test_other_validation_errors_keep_their_messages():
    # Duplicate alert_id and bad config still surface the original errors even
    # when the audit is requested, and no partial audit is produced.
    with pytest.raises(ValueError, match="duplicate alert_id"):
        process(
            payload(
                [],
                [alert("a1", 10), alert("a1", 20)],
                include_suppression_audit=True,
            )
        )
    with pytest.raises(ValueError, match="invalid downsample_ms"):
        process(
            {
                "downsample_ms": 0,
                "suppression_ms": 0,
                "metrics": [],
                "alerts": [],
                "include_suppression_audit": True,
            }
        )


# -- MetricBatchService -------------------------------------------------------


def make_service(**kwargs):
    options = dict(downsample_ms=1000, suppression_ms=100)
    options.update(kwargs)
    return MetricBatchService(**options)


def test_service_query_shape_and_empty_state():
    service = make_service()
    assert service.query_suppression_audit() == []


def test_service_reflects_patches_and_retractions():
    service = make_service(suppression_ms=100)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [],
            "alerts": [alert("a1", 0)],
        }
    )
    service.apply_batch(
        {
            "batch_id": "b2",
            "max_event_time_ms": 900,
            "metrics": [],
            "alerts": [alert("a2", 50)],
        }
    )
    audit = service.query_suppression_audit()
    assert audit[0]["suppressed"] is False
    assert audit[1] == {
        "alert_id": "a2",
        "suppressed": True,
        "causes": [{"kind": "time", "id": None}],
    }
    # Retracting the anchor batch re-adjudicates: a2 is no longer suppressed.
    service.retract_batch("b1")
    assert service.query_suppression_audit() == [
        {"alert_id": "a2", "suppressed": False, "causes": []}
    ]
    # Retracting the alert's own batch removes its record entirely.
    service.retract_batch("b2")
    assert service.query_suppression_audit() == []


def test_service_idempotent_replay_and_double_retract_add_no_records():
    service = make_service(maintenance_windows=[maintenance_window()])
    metrics_batch = {"batch_id": "b0", "max_event_time_ms": 900, "metrics": [sample(0)]}
    service.apply_batch(metrics_batch)
    alerts_batch = {
        "batch_id": "b1",
        "max_event_time_ms": 900,
        "metrics": [],
        "alerts": [alert("a1", 10)],
    }
    service.apply_batch(alerts_batch)
    once = service.query_suppression_audit()
    assert len(once) == 1
    # Replaying a metrics-only batch is a no-op success and changes nothing.
    service.apply_batch(metrics_batch)
    assert service.query_suppression_audit() == once
    service.retract_batch("b1")
    assert service.query_suppression_audit() == []
    # A second retraction of the same id is an idempotent no-op.
    service.retract_batch("b1")
    assert service.query_suppression_audit() == []
    # Re-applying the same batch_id (patch flow) adjudicates fresh records.
    service.apply_batch(alerts_batch)
    assert service.query_suppression_audit() == once


def test_service_window_and_maintenance_recompute_on_query():
    service = make_service(window_suppression_rules=[window_rule()])
    service.apply_batch(
        {"batch_id": "b0", "max_event_time_ms": 900, "metrics": [sample(0)]}
    )
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [],
            "alerts": [alert("a1", 10)],
        }
    )
    assert service.query_suppression_audit()[0]["causes"] == [
        {"kind": "window_rule", "id": "w1"}
    ]
    # Replacing the maintenance configuration is reflected immediately.
    service.set_maintenance_windows([maintenance_window()])
    assert service.query_suppression_audit()[0]["causes"] == [
        {"kind": "window_rule", "id": "w1"},
        {"kind": "maintenance", "id": "m1"},
    ]
    service.set_maintenance_windows(None)
    assert service.query_suppression_audit()[0]["causes"] == [
        {"kind": "window_rule", "id": "w1"}
    ]


def test_service_explanation_mode_records_rule_causes():
    service = make_service(
        enable_explanations=True, suppression_rules=[suppression_rule()]
    )
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [],
            "alerts": [alert("a1", 0), alert("a2", 50)],
        }
    )
    audit = service.query_suppression_audit()
    assert audit[0]["causes"] == []
    assert audit[1]["causes"] == [{"kind": "suppression_rule", "id": "r1"}]
    # No baseline time causes exist in explanation mode.
    assert all(c["kind"] != "time" for record in audit for c in record["causes"])


def test_service_audit_query_is_read_only():
    service = make_service(
        window_suppression_rules=[window_rule()],
        maintenance_windows=[maintenance_window()],
    )
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0)],
            "alerts": [alert("a1", 10)],
        }
    )
    alerts_before = service.query_alerts()
    series_before = service.query_series()
    windows_before = [w["window_id"] for w in service.maintenance_windows]
    service.query_suppression_audit()
    service.query_suppression_audit()
    assert service.query_alerts() == alerts_before
    assert service.query_series() == series_before
    assert [w["window_id"] for w in service.maintenance_windows] == windows_before
    # query_alerts never leaks internal audit mappings.
    assert not any(key.startswith("_audit") for key in alerts_before)


# -- HTTP ---------------------------------------------------------------------


@pytest.fixture
def http_service():
    service = MetricBatchService(
        downsample_ms=1000,
        suppression_ms=100,
        window_suppression_rules=[window_rule()],
        maintenance_windows=[maintenance_window()],
    )
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


def test_http_get_audit_endpoint(http_service):
    service, _post, get = http_service
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0)],
            "alerts": [alert("a1", 10)],
        }
    )
    status, body = get("/v1/suppression_audit")
    assert status == 200
    assert body == {
        "suppression_audit": [
            {
                "alert_id": "a1",
                "suppressed": True,
                "causes": [
                    {"kind": "window_rule", "id": "w1"},
                    {"kind": "maintenance", "id": "m1"},
                ],
            }
        ]
    }
    # Query parameters must not break routing.
    status, body = get("/v1/suppression_audit?unused=1")
    assert status == 200 and "suppression_audit" in body


def test_http_get_audit_does_not_change_alerts_or_series(http_service):
    service, _post, get = http_service
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(0)],
            "alerts": [alert("a1", 10)],
        }
    )
    _, alerts_before = get("/v1/alerts")
    _, series_before = get("/v1/series")
    for _ in range(3):
        get("/v1/suppression_audit")
    _, alerts_after = get("/v1/alerts")
    _, series_after = get("/v1/series")
    assert alerts_after == alerts_before
    assert series_after == series_before


def test_http_process_invalid_flag_returns_400(http_service):
    _service, post, _get = http_service
    status, body = post(
        "/process",
        payload([], [], include_suppression_audit="true"),
    )
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid suppression audit"}


@pytest.mark.parametrize("flag", [True, False])
def test_http_process_accepts_booleans(http_service, flag):
    _service, post, _get = http_service
    status, body = post(
        "/process",
        payload([], [alert("a1", 10)], include_suppression_audit=flag),
    )
    assert status == 200
    if flag:
        assert body["suppression_audit"] == [
            {"alert_id": "a1", "suppressed": False, "causes": []}
        ]
    else:
        assert "suppression_audit" not in body


# -- CLI ----------------------------------------------------------------------


def test_cli_invalid_flag_exits_2(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(payload([], [], include_suppression_audit=1)),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-m", "metric_fusion", str(request_file)],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "invalid suppression audit" in completed.stderr


def test_cli_audit_output_exits_0(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(
            payload(
                [],
                [alert("a1", 0), alert("a2", 50)],
                include_suppression_audit=True,
                suppression_ms=100,
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
    body = json.loads(completed.stdout)
    assert body["suppression_audit"][1]["causes"] == [{"kind": "time", "id": None}]
