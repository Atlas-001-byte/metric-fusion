"""Tests for planned-maintenance alert suppression windows."""

import json
import threading
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import pytest

from metric_fusion import (
    MaintenanceWindowError,
    MetricBatchService,
    process,
)
from metric_fusion.server import _make_handler


def sample(ts, source="agent-a", name="cpu.usage", labels=None, value=1.0):
    return {
        "source": source,
        "name": name,
        "labels": {"host": "db-1"} if labels is None else labels,
        "timestamp_ms": ts,
        "value": value,
    }


def alert(alert_id, ts, source="agent-a", name="cpu.usage", labels=None,
          severity="warning", rule="cpu-high"):
    return {
        "source": source,
        "name": name,
        "labels": {"host": "db-1"} if labels is None else labels,
        "alert_id": alert_id,
        "rule": rule,
        "timestamp_ms": ts,
        "severity": severity,
    }


def window(window_id="w1", start_ms=100, end_ms=200, **conditions):
    item = {"window_id": window_id, "start_ms": start_ms, "end_ms": end_ms}
    item.update(conditions)
    return item


def payload(metrics=None, alerts=None, **extra):
    request = {
        "downsample_ms": 1000,
        "suppression_ms": 0,
        "metrics": [] if metrics is None else metrics,
        "alerts": [] if alerts is None else alerts,
    }
    request.update(extra)
    return request


# -- validation ----------------------------------------------------------------


def test_window_requires_at_least_one_condition():
    with pytest.raises(MaintenanceWindowError, match="^invalid maintenance_window$"):
        process(payload(alerts=[alert("a1", 150)], maintenance_windows=[window()]))


@pytest.mark.parametrize(
    "patch",
    [
        {"window_id": ""},
        {"window_id": None},
        {"window_id": 5},
        {"start_ms": -1},
        {"start_ms": float("inf")},
        {"start_ms": float("nan")},
        {"start_ms": True},
        {"start_ms": None},
        {"end_ms": -1},
        {"end_ms": float("inf")},
        {"end_ms": "200"},
        {"end_ms": 50},            # end <= start
        {"end_ms": 100},           # end == start
        {"source": ""},
        {"source": 1},
        {"name": ""},
        {"labels": "nope"},
        {"labels": {"": "x"}},
        {"labels": {5: "x"}},
        {"labels": {None: "x"}},
    ],
)
def test_invalid_window_fields(patch):
    base = window(source="agent-a")
    base.update(patch)
    with pytest.raises(MaintenanceWindowError, match="^invalid maintenance_window$"):
        process(payload(alerts=[alert("a1", 150)], maintenance_windows=[base]))


def test_non_list_payload_rejected():
    with pytest.raises(MaintenanceWindowError):
        process(payload(alerts=[alert("a1", 150)], maintenance_windows={"source": "agent-a"}))
    with pytest.raises(MaintenanceWindowError):
        process(payload(alerts=[alert("a1", 150)], maintenance_windows="nope"))


def test_duplicate_window_ids_rejected():
    with pytest.raises(MaintenanceWindowError):
        process(
            payload(
                alerts=[alert("a1", 150)],
                maintenance_windows=[
                    window("w1", source="agent-a"),
                    window("w1", 100, 300, name="cpu.usage"),
                ],
            )
        )


def test_validation_is_all_or_nothing():
    service = MetricBatchService(downsample_ms=1000)
    service.set_maintenance_windows([window("w1", source="agent-a")])
    with pytest.raises(MaintenanceWindowError):
        service.set_maintenance_windows([window("w2", source="agent-a"), window("w2")])
    result = service.query_alerts()
    # No data yet, but the surviving configuration must still govern afterwards.
    assert result["suppressed_alert_ids"] == []
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [], "alerts": [alert("a1", 150)]}
    )
    assert service.query_alerts()["suppressed_alert_ids"] == ["a1"]


def test_constructor_rejects_invalid_windows():
    with pytest.raises(MaintenanceWindowError):
        MetricBatchService(maintenance_windows=[window()])


# -- process() suppression semantics -------------------------------------------


def test_basic_timestamp_suppression_half_open_interval():
    result = process(
        payload(
            alerts=[
                alert("before", 99),
                alert("at_start", 100),
                alert("inside", 150),
                alert("at_end", 200),
                alert("after", 201),
            ],
            maintenance_windows=[window(source="agent-a")],
        )
    )
    statuses = {a["alert_id"]: a["suppressed"] for a in result["alerts"]}
    assert statuses == {
        "before": False,
        "at_start": True,
        "inside": True,
        "at_end": False,  # right-open
        "after": False,
    }
    assert result["suppressed_alert_ids"] == ["at_start", "inside"]
    # Alert fields, order and shape are unchanged.
    assert [a["alert_id"] for a in result["alerts"]] == [
        "before", "at_start", "inside", "at_end", "after"
    ]
    assert set(result["alerts"][0]) == {"alert_id", "severity", "suppressed"}


def test_no_maintenance_windows_means_unchanged_output():
    result = process(payload(alerts=[alert("a1", 150)]))
    assert set(result) == {"series", "alerts", "suppressed_alert_ids"}
    assert result["alerts"][0]["suppressed"] is False


def test_empty_window_list_is_explicit_but_suppresses_nothing():
    result = process(payload(alerts=[alert("a1", 150)], maintenance_windows=[]))
    assert result["suppressed_alert_ids"] == []
    assert "suppression_states" not in result


def test_source_name_labels_must_all_match():
    alerts = [
        alert("a1", 150, source="agent-a", name="cpu.usage", labels={"host": "db-1"}),
        alert("a2", 151, source="agent-b", name="cpu.usage", labels={"host": "db-1"}),
        alert("a3", 152, source="agent-a", name="disk.usage", labels={"host": "db-1"}),
        alert("a4", 153, source="agent-a", name="cpu.usage", labels={"host": "db-2"}),
        alert("a5", 154, source="agent-a", name="cpu.usage",
              labels={"host": "db-1", "rack": "r1"}),
    ]
    result = process(
        payload(
            alerts=alerts,
            maintenance_windows=[
                window(source="agent-a", name="cpu.usage", labels={"host": "db-1"})
            ],
        )
    )
    suppressed = dict(
        (a["alert_id"], a["suppressed"]) for a in result["alerts"]
    )
    assert suppressed == {
        "a1": True, "a2": False, "a3": False, "a4": False, "a5": True
    }


def test_label_subset_matching():
    result = process(
        payload(
            alerts=[
                alert("a1", 150, labels={"host": "db-1", "rack": "r1"}),
                alert("a2", 150, labels={"host": "db-2", "rack": "r1"}),
            ],
            maintenance_windows=[window(labels={"rack": "r1"})],
        )
    )
    assert result["suppressed_alert_ids"] == ["a1", "a2"]


def test_label_values_can_be_non_strings_but_must_match_exactly():
    result = process(
        payload(
            alerts=[
                alert("a1", 150, labels={"port": 8080, "secure": True}),
                alert("a2", 151, labels={"port": 9090, "secure": True}),
                alert("a3", 152, labels={"port": "8080", "secure": True}),
            ],
            maintenance_windows=[window(labels={"port": 8080, "secure": True})],
        )
    )
    # a3's string "8080" does not equal the numeric 8080 condition.
    assert result["suppressed_alert_ids"] == ["a1"]


def test_multiple_windows_match_and_ids_are_unique():
    result = process(
        payload(
            alerts=[alert("a1", 150)],
            maintenance_windows=[
                window("w1", source="agent-a"),
                window("w2", name="cpu.usage"),
            ],
        )
    )
    assert result["suppressed_alert_ids"] == ["a1"]


def test_union_with_time_based_suppression():
    # suppression_ms chain: same rule/name/labels, a2 within 300ms of a1 and
    # no higher severity -> suppressed by the baseline logic. Maintenance
    # window independently catches a3.
    alerts = [
        alert("a1", 0),
        alert("a2", 100),
        alert("a3", 150, name="disk.usage"),
    ]
    result = process(
        payload(
            alerts=alerts,
            suppression_ms=300,
            maintenance_windows=[window(name="disk.usage")],
        )
    )
    assert result["suppressed_alert_ids"] == ["a2", "a3"]
    by_id = {a["alert_id"]: a for a in result["alerts"]}
    assert by_id["a1"]["suppressed"] is False
    assert by_id["a2"]["suppressed"] is True
    assert by_id["a3"]["suppressed"] is True


def test_higher_severity_breakthrough_still_emits_outside_window():
    alerts = [
        alert("a1", 0, severity="warning"),
        alert("a2", 100, severity="critical"),
    ]
    result = process(
        payload(alerts=alerts, suppression_ms=300,
                maintenance_windows=[window("w1", 500, 600, source="agent-a")])
    )
    assert result["suppressed_alert_ids"] == []


def test_float_timestamps_supported():
    result = process(
        payload(
            alerts=[alert("a1", 150.25)],
            maintenance_windows=[window("w1", 100.0, 200.0, source="agent-a")],
        )
    )
    assert result["suppressed_alert_ids"] == ["a1"]


def test_series_aggregations_and_quorum_unaffected():
    metrics = [sample(0, "a"), sample(100, "b")]
    result = process(
        payload(
            metrics=metrics,
            alerts=[alert("a1", 150)],
            aggregations={"cpu.usage": "max"},
            source_quorum={"cpu.usage": 2},
            maintenance_windows=[window(source="agent-a")],
        )
    )
    assert len(result["series"]) == 1
    assert result["series"][0]["value"] == 1.0


# -- explanation mode -----------------------------------------------------------


def test_explanation_mode_uses_suppressed_status():
    alerts = [
        alert("a1", 0),
        alert("a2", 150, name="other"),  # suppressed only by maintenance
        alert("a3", 100),                # within the rule window of a1
    ]
    result = process(
        payload(
            alerts=alerts,
            suppression_ms=300,
            enable_explanations=True,
            suppression_rules=[
                {
                    "rule_id": "r1",
                    "selector": {"metric": "cpu.usage", "labels": {"host": "db-1"}},
                    "min_severity": "info",
                    "suppression_ms": 300,
                }
            ],
            maintenance_windows=[window(name="other")],
        )
    )
    statuses = {a["alert_id"]: a["status"] for a in result["alerts"]}
    assert statuses == {"a1": "active", "a2": "suppressed", "a3": "suppressed"}
    # Maintenance suppression adds no explanation record of its own.
    assert {e["suppressed_fingerprint"] for e in result["explanations"]} == {
        next(a["fingerprint"] for a in result["alerts"] if a["alert_id"] == "a3")
    }
    assert result["suppressed_alert_ids"] == ["a2", "a3"]
    # Original fields and fingerprint survive; order unchanged.
    assert [a["alert_id"] for a in result["alerts"]] == ["a1", "a2", "a3"]
    assert result["alerts"][1]["name"] == "other"


# -- MetricBatchService ----------------------------------------------------------


def make_service():
    return MetricBatchService(
        downsample_ms=1000,
        maintenance_windows=[window("w1", source="agent-a")],
    )


def test_service_configuration_applies_to_stored_alerts():
    service = make_service()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [],
         "alerts": [alert("a1", 150), alert("a2", 250)]}
    )
    result = service.query_alerts()
    assert result["suppressed_alert_ids"] == ["a1"]


def test_service_set_windows_full_replace():
    service = make_service()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [],
         "alerts": [
             alert("a1", 150, source="agent-a"),
             alert("a2", 151, source="agent-b"),
         ]}
    )
    assert service.query_alerts()["suppressed_alert_ids"] == ["a1"]

    service.set_maintenance_windows([window("w2", source="agent-b")])
    result = service.query_alerts()
    assert result["suppressed_alert_ids"] == ["a2"]

    service.set_maintenance_windows([])
    assert service.query_alerts()["suppressed_alert_ids"] == []


def test_service_reset_keeps_configuration():
    service = make_service()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [],
         "alerts": [alert("a1", 150)]}
    )
    assert service.query_alerts()["suppressed_alert_ids"] == ["a1"]
    service.reset()
    assert service.query_alerts()["suppressed_alert_ids"] == []
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900, "metrics": [],
         "alerts": [alert("a2", 150)]}
    )
    assert service.query_alerts()["suppressed_alert_ids"] == ["a2"]


def test_service_rejudges_after_late_patch_and_retraction():
    service = MetricBatchService(downsample_ms=1000)
    service.set_maintenance_windows([window("w1", 100, 300, name="cpu.usage")])
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [],
         "alerts": [alert("a1", 50)]}
    )
    assert service.query_alerts()["suppressed_alert_ids"] == []

    # Late arrival of an alert inside the window.
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 900, "metrics": [],
         "alerts": [alert("a2", 150)]}
    )
    assert service.query_alerts()["suppressed_alert_ids"] == ["a2"]

    # Retraction removes it; the remaining set is re-judged.
    service.retract_batch("b2")
    assert service.query_alerts()["suppressed_alert_ids"] == []


def test_service_invalid_set_changes_nothing():
    service = make_service()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [],
         "alerts": [alert("a1", 150)]}
    )
    with pytest.raises(MaintenanceWindowError):
        service.set_maintenance_windows([window("bad")])  # no conditions
    assert service.query_alerts()["suppressed_alert_ids"] == ["a1"]


def test_batch_requests_do_not_read_maintenance_windows():
    """maintenance_windows belongs to process/config; batches ignore it."""
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [],
            "alerts": [alert("a1", 150)],
            "maintenance_windows": [window(source="agent-a")],
        }
    )
    # The service keeps no configured windows, so re-querying emits the alert.
    assert service.query_alerts()["suppressed_alert_ids"] == []

    # Even an ill-formed field on a batch request is simply ignored.
    service.apply_batch(
        {
            "batch_id": "b2",
            "max_event_time_ms": 900,
            "metrics": [],
            "alerts": [],
            "maintenance_windows": [window()],
        }
    )


def test_query_series_does_not_read_windows():
    service = make_service()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 1900, "metrics": [sample(1000)]}
    )
    rows = service.query_series()
    assert len(rows) == 1


# -- HTTP ------------------------------------------------------------------------


@pytest.fixture
def http_server():
    service = MetricBatchService(downsample_ms=1000)
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), _make_handler(service, threading.Lock())
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield service, f"http://{host}:{port}"
    server.shutdown()
    server.server_close()


def _request(base, method, path, payload_obj):
    body = json.dumps(payload_obj).encode("utf-8")
    req = Request(base + path, data=body, method=method,
                  headers={"Content-Type": "application/json"})
    return urlopen(req)


def test_http_put_and_post_replace_windows(http_server):
    service, base = http_server
    for index, method in enumerate(("PUT", "POST")):
        windows = [window(f"w{index}", source=f"agent-{method}")]
        with _request(
            base, method, "/v1/maintenance_windows", windows
        ) as resp:
            assert resp.status == 200
            assert json.loads(resp.read()) == {"status": "ok"}

        # Wrapped-object shape replaces the configuration as well.
        with _request(
            base, method, "/v1/maintenance_windows",
            {"maintenance_windows": [window(f"x{index}", name=f"svc-{method}")]},
        ) as resp:
            assert resp.status == 200

        service.apply_batch(
            {"batch_id": f"b-{method}", "max_event_time_ms": 900, "metrics": [],
             "alerts": [
                 alert(f"a-{method}", 150, source="agent-x", name=f"svc-{method}"),
             ]}
        )
        assert service.query_alerts()["suppressed_alert_ids"] == [f"a-{method}"]


def test_http_invalid_windows_return_400_and_keep_state(http_server):
    service, base = http_server
    service.set_maintenance_windows([window("w1", source="agent-a")])
    for body in (
        [window()],
        {"maintenance_windows": [window("w1"), window("w1", source="x")]},
        {"maintenance_windows": "nope"},
    ):
        try:
            _request(base, "PUT", "/v1/maintenance_windows", body)
        except HTTPError as exc:
            assert exc.code == 400
            assert json.loads(exc.read()) == {
                "code": "invalid_maintenance_window",
                "message": "invalid maintenance_window",
            }
        else:
            pytest.fail("expected HTTP 400")

    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [],
         "alerts": [alert("a1", 150)]}
    )
    assert service.query_alerts()["suppressed_alert_ids"] == ["a1"]


def test_http_process_invalid_windows_return_400(http_server):
    _service, base = http_server
    try:
        _request(
            base, "POST", "/process",
            payload(alerts=[alert("a1", 150)], maintenance_windows=[window()]),
        )
    except HTTPError as exc:
        assert exc.code == 400
        assert json.loads(exc.read())["code"] == "invalid_maintenance_window"
    else:
        pytest.fail("expected HTTP 400")


def test_http_alerts_reflect_windows(http_server):
    service, base = http_server
    with _request(
        base, "PUT", "/v1/maintenance_windows", [window(source="agent-a")]
    ) as resp:
        resp.read()
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [],
         "alerts": [alert("a1", 150), alert("a2", 250)]}
    )
    with urlopen(base + "/v1/alerts") as resp:
        body = json.loads(resp.read())
    assert body["suppressed_alert_ids"] == ["a1"]


# -- CLI --------------------------------------------------------------------------


def test_cli_prints_message_and_exits_2(tmp_path, capsys):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(payload(alerts=[alert("a1", 150)], maintenance_windows=[window()])),
        encoding="utf-8",
    )
    from metric_fusion.__main__ import main

    exit_code = main([str(request_file)])
    assert exit_code == 2
    assert capsys.readouterr().err.strip() == "invalid maintenance_window"


def test_cli_success_output(tmp_path, capsys):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps(
            payload(alerts=[alert("a1", 150)],
                    maintenance_windows=[window(source="agent-a")])
        ),
        encoding="utf-8",
    )
    from metric_fusion.__main__ import main

    exit_code = main([str(request_file)])
    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["suppressed_alert_ids"] == ["a1"]
