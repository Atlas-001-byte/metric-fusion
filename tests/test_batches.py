"""Tests for batched metric patches, idempotency and late-data correction."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from metric_fusion import (
    BatchError,
    MetricStore,
    apply_metric_batch,
    process,
    query_batch_alerts,
    query_series,
    reset_batches,
)
from metric_fusion.server import create_handler
from http.server import ThreadingHTTPServer


def _metric(source="s1", name="cpu.usage", labels=None, ts=100, value=10.0):
    return {
        "source": source,
        "name": name,
        "labels": labels if labels is not None else {"host": "a"},
        "timestamp_ms": ts,
        "value": value,
    }


def _alert(alert_id, name="cpu.usage", labels=None, severity="warning", ts=1000,
           rule="r"):
    return {
        "source": "s1",
        "name": name,
        "labels": labels if labels is not None else {"host": "a"},
        "alert_id": alert_id,
        "rule": rule,
        "timestamp_ms": ts,
        "severity": severity,
    }


def _batch(batch_id="b1", metrics=None, alerts=None, *, max_event_time_ms=10000,
           downsample_ms=1000, suppression_ms=5000, **extra):
    request = {"batch_id": batch_id}
    if metrics is not None:
        request["metrics"] = metrics
    if alerts is not None:
        request["alerts"] = alerts
    if max_event_time_ms is not None:
        request["max_event_time_ms"] = max_event_time_ms
    if downsample_ms is not None:
        request["downsample_ms"] = downsample_ms
    if suppression_ms is not None:
        request["suppression_ms"] = suppression_ms
    request.update(extra)
    return request


RULE = {
    "rule_id": "r1",
    "selector": {"metric": "cpu.usage", "labels": {"host": "a"}},
    "min_severity": "info",
    "suppression_ms": 5000,
}


# --- successful application ------------------------------------------------


def test_apply_batch_receipt_and_aggregation():
    store = MetricStore(downsample_ms=1000)
    receipt = store.apply_batch(
        _batch("b1", metrics=[_metric("s1", ts=100, value=10),
                              _metric("s2", ts=200, value=20)])
    )
    assert receipt == {
        "batch_id": "b1",
        "status": "applied",
        "affected_streams": 1,
        "recomputed_windows": 1,
    }
    (point,) = store.query_series()
    assert point == {
        "name": "cpu.usage",
        "labels": {"host": "a"},
        "timestamp_ms": 0,
        "value": 15.0,
        "count": 2,
        "sources": ["s1", "s2"],
    }


def test_recomputed_windows_counts_distinct_windows_and_streams():
    store = MetricStore(downsample_ms=1000)
    receipt = store.apply_batch(
        _batch(
            "b1",
            metrics=[
                _metric("s1", ts=100),
                _metric("s1", ts=1200),             # second window, same stream
                _metric("s1", labels={"host": "b"}, ts=100),  # second stream
            ],
        )
    )
    assert receipt["affected_streams"] == 2
    assert receipt["recomputed_windows"] == 3


def test_batch_without_id_follows_legacy_entry():
    store = MetricStore(downsample_ms=1000)
    request = _batch(None, metrics=[_metric(ts=100, value=10)],
                     max_event_time_ms=None)
    receipt = store.apply_batch(request)
    assert receipt["batch_id"] is None
    assert receipt["status"] == "applied"
    # No idempotency record: reapplying re-processes (same identity wins, so the
    # aggregated value is stable) and reports effects again.
    receipt2 = store.apply_batch(request)
    assert receipt2["status"] == "applied"
    assert receipt2["affected_streams"] == 1
    assert receipt2["recomputed_windows"] == 1
    assert store.query_series()[0]["value"] == 10.0


def test_legacy_batch_omits_watermark_and_grid_from_store_config():
    store = MetricStore()  # no configured grid
    receipt = store.apply_batch(
        _batch(None, metrics=[_metric(ts=100)], max_event_time_ms=None,
               downsample_ms=1000)
    )
    assert receipt["status"] == "applied"
    assert store.query_series()[0]["timestamp_ms"] == 0


# --- idempotency ------------------------------------------------------------


def test_exact_duplicate_is_already_applied_with_zero_counts():
    store = MetricStore(downsample_ms=1000)
    first = _batch("b1", metrics=[_metric(ts=100, value=10)])
    assert store.apply_batch(first)["status"] == "applied"
    repeat = store.apply_batch(json.loads(json.dumps(first)))
    assert repeat == {
        "batch_id": "b1",
        "status": "already_applied",
        "affected_streams": 0,
        "recomputed_windows": 0,
    }
    assert len(store.query_series()) == 1


def test_duplicate_content_different_sample_order_still_identical():
    store = MetricStore(downsample_ms=1000)
    first = _batch("b1", metrics=[_metric("s1", ts=100, value=1),
                                  _metric("s2", ts=200, value=2)])
    store.apply_batch(first)
    reordered = _batch("b1", metrics=[_metric("s2", ts=200, value=2),
                                      _metric("s1", ts=100, value=1)])
    assert store.apply_batch(reordered)["status"] == "already_applied"


def test_conflicting_duplicate_rejected_with_pinned_code():
    store = MetricStore(downsample_ms=1000)
    store.apply_batch(_batch("b1", metrics=[_metric(ts=100, value=10)]))
    conflicting = _batch("b1", metrics=[_metric(ts=100, value=99)])
    with pytest.raises(BatchError) as exc_info:
        store.apply_batch(conflicting)
    assert exc_info.value.code == "metric_batch_conflict"
    assert exc_info.value.http_status == 409
    # Whole divergent batch rejected: original aggregation survives.
    assert store.query_series()[0]["value"] == 10.0


def test_conflict_on_different_watermark():
    store = MetricStore(downsample_ms=1000)
    store.apply_batch(_batch("b1", metrics=[_metric(ts=100)],
                             max_event_time_ms=1000))
    with pytest.raises(BatchError, match="metric_batch_conflict"):
        store.apply_batch(_batch("b1", metrics=[_metric(ts=100)],
                                 max_event_time_ms=2000))


def test_duplicate_compares_values_numerically():
    store = MetricStore(downsample_ms=1000)
    store.apply_batch(_batch("b1", metrics=[_metric(ts=100, value=10)]))
    # int/float spellings of the same value are the same content.
    same = _batch("b1", metrics=[_metric(ts=100.0, value=10.0)])
    assert store.apply_batch(same)["status"] == "already_applied"
    with pytest.raises(BatchError):
        store.apply_batch(_batch("b1", metrics=[_metric(ts=100, value=10.5)]))


# --- range validation -------------------------------------------------------


def test_timestamp_after_watermark_rejected_400():
    store = MetricStore(downsample_ms=1000)
    batch = _batch("b1", metrics=[_metric(ts=5000)], max_event_time_ms=4000)
    with pytest.raises(BatchError) as exc_info:
        store.apply_batch(batch)
    assert exc_info.value.code == "metric_batch_range_invalid"
    assert exc_info.value.http_status == 400
    assert store.query_series() == []


def test_timestamp_equal_to_watermark_is_inside_range():
    store = MetricStore(downsample_ms=1000)
    receipt = store.apply_batch(
        _batch("b1", metrics=[_metric(ts=1000)], max_event_time_ms=1000)
    )
    assert receipt["status"] == "applied"
    assert store.query_series()[0]["timestamp_ms"] == 1000


def test_timestamp_inside_its_window_is_accepted():
    store = MetricStore(downsample_ms=1000)
    # Sample at the last millisecond of window [1000, 2000) belongs there.
    receipt = store.apply_batch(
        _batch("b1", metrics=[_metric(ts=1999)], max_event_time_ms=2000)
    )
    assert receipt["status"] == "applied"
    assert store.query_series()[0]["timestamp_ms"] == 1000


def test_range_rejection_is_atomic():
    store = MetricStore(downsample_ms=1000)
    store.apply_batch(_batch("b1", metrics=[_metric(ts=100, value=10)]))
    with pytest.raises(BatchError):
        store.apply_batch(
            _batch("b2",
                   metrics=[_metric(ts=200, value=20), _metric(ts=9999, value=1)],
                   max_event_time_ms=5000)
        )
    # The in-range sample from the rejected batch must not be partially applied.
    assert store.query_series()[0]["value"] == 10.0


# --- unresolved windows -----------------------------------------------------


def test_samples_without_resolvable_grid_return_422():
    store = MetricStore()
    with pytest.raises(BatchError) as exc_info:
        store.apply_batch(_batch("b1", metrics=[_metric(ts=100)],
                                 downsample_ms=None))
    assert exc_info.value.code == "metric_window_unresolved"
    assert exc_info.value.http_status == 422
    assert store.query_series() == []


def test_alerts_only_batch_without_grid_is_fine():
    store = MetricStore(suppression_ms=5000)
    receipt = store.apply_batch(
        _batch("b1", alerts=[_alert("a1", ts=1000)], downsample_ms=None)
    )
    assert receipt["affected_streams"] == 0
    assert receipt["recomputed_windows"] == 0
    assert len(store.query_alerts()) == 1


def test_grid_can_be_carried_by_batch_then_reused():
    store = MetricStore()
    store.apply_batch(_batch("b1", metrics=[_metric(ts=100)],
                             downsample_ms=1000))
    # Later batch need not repeat the grid; windows are still resolvable.
    receipt = store.apply_batch(_batch("b2", metrics=[_metric(ts=1200)],
                                       downsample_ms=None))
    assert receipt["status"] == "applied"
    assert {p["timestamp_ms"] for p in store.query_series()} == {0, 1000}


def test_conflicting_grid_rejected_as_validation_error():
    store = MetricStore(downsample_ms=1000)
    with pytest.raises(ValueError, match="invalid downsample_ms"):
        store.apply_batch(_batch("b1", metrics=[_metric(ts=100)],
                                 downsample_ms=5000))


# --- late-data correction ---------------------------------------------------


def test_late_sample_recomputes_only_its_window():
    store = MetricStore(downsample_ms=1000)
    store.apply_batch(_batch("b1", metrics=[_metric(ts=0, value=10)],
                             max_event_time_ms=1000))
    assert store.query_series()[0]["value"] == 10.0

    receipt = store.apply_batch(
        _batch("b2", metrics=[_metric(ts=500, value=20)],
               max_event_time_ms=2000)
    )
    assert receipt["recomputed_windows"] == 1
    point = store.query_series(name="cpu.usage", labels={"host": "a"})[0]
    assert point["count"] == 2
    assert point["value"] == 15.0


def test_late_sample_does_not_touch_unrelated_windows():
    store = MetricStore(downsample_ms=1000)
    store.apply_batch(_batch("b1", metrics=[_metric(ts=0, value=10),
                                           _metric(ts=1000, value=30)]))
    receipt = store.apply_batch(
        _batch("b2", metrics=[_metric(ts=200, value=20)],
               max_event_time_ms=2000)
    )
    assert receipt["recomputed_windows"] == 1
    by_window = {p["timestamp_ms"]: p for p in store.query_series()}
    assert by_window[0]["value"] == 15.0
    assert by_window[1000]["value"] == 30.0  # untouched


def test_late_alert_batch_readjudicates_suppression():
    store = MetricStore(downsample_ms=1000, suppression_ms=5000)
    store.apply_batch(
        _batch("b1", alerts=[_alert("a2", ts=2000), _alert("a3", ts=3000)])
    )
    outcomes = {a["alert_id"]: a["suppressed"] for a in store.query_alerts()}
    assert outcomes == {"a2": False, "a3": True}

    # Late arrival of an earlier alert changes the chain: a2/a3 now both fall
    # inside a1's suppression window.
    store.apply_batch(_batch("b2", alerts=[_alert("a1", ts=1000)],
                             max_event_time_ms=5000))
    outcomes = {a["alert_id"]: a["suppressed"] for a in store.query_alerts()}
    assert outcomes == {"a1": False, "a2": True, "a3": True}


def test_late_correction_can_withdraw_suppression_and_explanations():
    store = MetricStore(
        downsample_ms=1000,
        enable_explanations=True,
        suppression_rules=[RULE],
    )
    # a1 at 3000 is active; a2 at 5001 is within 5000ms of a1 -> suppressed.
    store.apply_batch(
        _batch("b1", alerts=[_alert("a1", ts=3000), _alert("a2", ts=5001)])
    )
    statuses = {a["alert_id"]: a["status"] for a in store.query_alerts()}
    assert statuses == {"a1": "active", "a2": "suppressed"}
    explanations = store.query_explanations(now_ms=100000)
    assert len(explanations) == 1

    # Late arrival of a0 at 0 restarts the active chain: a1 is now within
    # a0's window (suppressed), while a2 falls 5001ms after the only active
    # anchor a0 and must be emitted -- the old suppression is withdrawn.
    store.apply_batch(
        _batch("b2", alerts=[_alert("a0", ts=0)], max_event_time_ms=10000)
    )
    statuses = {a["alert_id"]: a["status"] for a in store.query_alerts()}
    assert statuses == {"a0": "active", "a1": "suppressed", "a2": "active"}
    explanations = store.query_explanations(now_ms=100000)
    # Stale explanation for a2 is gone; the new one explains a1 instead.
    assert len(explanations) == 1
    fp_a1 = [a for a in store.query_alerts() if a["alert_id"] == "a1"][0]["fingerprint"]
    assert explanations[0]["suppressed_fingerprint"] == fp_a1


def test_divergent_alert_reusing_alert_id_rejected_across_batches():
    store = MetricStore(downsample_ms=1000, suppression_ms=5000)
    store.apply_batch(_batch("b1", alerts=[_alert("a1", ts=1000)]))
    # Identical redelivery merges as a no-op.
    store.apply_batch(_batch("b2", alerts=[_alert("a1", ts=1000)],
                             max_event_time_ms=2000))
    # Divergent record with the same id is rejected atomically.
    with pytest.raises(ValueError, match="duplicate alert_id"):
        store.apply_batch(_batch("b3", alerts=[_alert("a1", ts=9999)],
                                 max_event_time_ms=10000))
    assert len(store.query_alerts()) == 1


# --- ordering, determinism, queries ----------------------------------------


def test_batch_arrival_order_does_not_change_final_values():
    def run(order):
        store = MetricStore(downsample_ms=1000, suppression_ms=5000)
        batches = [
            _batch("b1", metrics=[_metric(ts=0, value=10)],
                   alerts=[_alert("a1", ts=1000)], max_event_time_ms=1000),
            _batch("b2", metrics=[_metric(ts=500, value=20),
                                  _metric("s2", ts=1000, value=40)],
                   alerts=[_alert("a2", ts=2000)], max_event_time_ms=2000),
            _batch("b3", metrics=[_metric(ts=2100, value=5)],
                   alerts=[_alert("a3", ts=9000)], max_event_time_ms=10000),
        ]
        for index in order:
            store.apply_batch(batches[index])
        return store.query_series(), store.query_alerts()

    series_a, alerts_a = run([0, 1, 2])
    series_b, alerts_b = run([2, 0, 1])
    assert series_a == series_b
    assert alerts_a == alerts_b


def test_same_input_set_replayed_is_deterministic():
    batches = [
        _batch("b1", metrics=[_metric(ts=0, value=10)]),
        _batch("b2", metrics=[_metric(ts=100, value=20),
                              _metric("s2", ts=200, value=30)]),
    ]
    outcomes = []
    for _ in range(2):
        store = MetricStore(downsample_ms=1000)
        for batch in batches:
            store.apply_batch(json.loads(json.dumps(batch)))
        outcomes.append(store.query_series())
    assert outcomes[0] == outcomes[1]


def test_series_query_sorting_and_time_range():
    store = MetricStore(downsample_ms=1000)
    store.apply_batch(
        _batch(
            "b1",
            metrics=[
                _metric("s1", name="b.metric", ts=0),
                _metric("s1", name="a.metric", labels={"host": "z"}, ts=5000),
                _metric("s1", name="a.metric", labels={"host": "a"}, ts=0),
                _metric("s1", name="a.metric", labels={"host": "a"}, ts=1000),
            ],
        )
    )
    keys = [(p["name"], _labels_key(p["labels"]), p["timestamp_ms"])
            for p in store.query_series()]
    assert keys == sorted(keys)

    window_starts = [
        p["timestamp_ms"]
        for p in store.query_series(name="a.metric", start_ms=1000, end_ms=1000)
    ]
    assert window_starts == [1000]

    only_host_a = store.query_series(labels={"host": "a"})
    assert all(p["labels"] == {"host": "a"} for p in only_host_a)
    assert len(only_host_a) == 3


def _labels_key(labels):
    return json.dumps(labels, sort_keys=True, separators=(",", ":"))


# --- validation and atomicity ----------------------------------------------


def test_batch_id_must_be_nonempty_string():
    store = MetricStore(downsample_ms=1000)
    for bad in (123, "", ["x"]):
        with pytest.raises(ValueError, match="invalid batch_id"):
            store.apply_batch(_batch(bad, metrics=[_metric()]))


def test_watermark_required_for_identified_batch():
    store = MetricStore(downsample_ms=1000)
    with pytest.raises(ValueError, match="invalid max_event_time_ms"):
        store.apply_batch(_batch("b1", metrics=[_metric()],
                                 max_event_time_ms=None))
    with pytest.raises(ValueError, match="invalid max_event_time_ms"):
        store.apply_batch(_batch("b1", metrics=[_metric()],
                                 max_event_time_ms="later"))


def test_metric_shape_errors_are_plain_value_errors_and_atomic():
    store = MetricStore(downsample_ms=1000)
    with pytest.raises(ValueError, match="invalid metric"):
        store.apply_batch(_batch("b1", metrics=[{"source": "s1"}]))
    with pytest.raises(ValueError, match="invalid value"):
        store.apply_batch(_batch("b1", metrics=[_metric(value=float("nan"))]))
    assert store.query_series() == []


def test_reset_clears_everything():
    store = MetricStore(downsample_ms=1000)
    store.apply_batch(_batch("b1", metrics=[_metric()],
                             alerts=[_alert("a1")]))
    store.reset()
    assert store.query_series() == []
    assert store.query_alerts() == []
    # batch_id can be reused as if never seen
    assert store.apply_batch(
        _batch("b1", metrics=[_metric(value=1)]))["status"] == "applied"


# --- legacy process entry point stays stateless and compatible -------------


def test_legacy_process_output_and_validation_unchanged():
    request = {
        "downsample_ms": 1000,
        "suppression_ms": 5000,
        "metrics": [_metric("s1", ts=100, value=10),
                    _metric("s2", ts=200, value=20)],
        "alerts": [_alert("a1", ts=1000), _alert("a2", ts=2000)],
    }
    result = process(request)
    assert set(result) == {"series", "alerts", "suppressed_alert_ids"}
    assert result["suppressed_alert_ids"] == ["a2"]
    assert result["series"][0]["value"] == 15.0
    with pytest.raises(ValueError, match="invalid downsample_ms"):
        process({**request, "downsample_ms": 0})


def test_batch_store_does_not_affect_legacy_process():
    store = MetricStore(downsample_ms=1000)
    store.apply_batch(_batch("b1", metrics=[_metric(value=100)]))
    result = process(
        {"downsample_ms": 1000, "suppression_ms": 0,
         "metrics": [_metric(value=1)], "alerts": []}
    )
    assert result["series"][0]["value"] == 1.0


def test_module_level_default_store_and_reset():
    reset_batches()
    try:
        receipt = apply_metric_batch(_batch("glob-1", metrics=[_metric()]))
        assert receipt["status"] == "applied"
        assert len(query_series()) == 1
        assert len(query_batch_alerts()) == 0
    finally:
        reset_batches()


# --- HTTP adapter -----------------------------------------------------------


class _HTTPServer:
    def __init__(self, store):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(store))
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


def _post(server, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        server.url("/batches"), data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _get(server, path):
    with urllib.request.urlopen(server.url(path), timeout=5) as resp:
        return resp.status, json.loads(resp.read())


@pytest.fixture
def server():
    store = MetricStore(downsample_ms=1000, suppression_ms=5000)
    server = _HTTPServer(store)
    yield server
    server.stop()


def test_http_apply_and_query(server):
    status, body = _post(server, _batch("b1", metrics=[_metric(ts=100, value=10),
                                                       _metric(ts=200, value=20)]))
    assert status == 200
    assert body == {"batch_id": "b1", "status": "applied",
                    "affected_streams": 1, "recomputed_windows": 1}
    status, body = _get(server, "/series?name=cpu.usage")
    assert status == 200
    assert body["series"][0]["value"] == 15.0
    status, body = _get(server, "/alerts")
    assert status == 200 and body["alerts"] == []


def test_http_duplicate_and_conflict_statuses(server):
    batch = _batch("b1", metrics=[_metric(ts=100, value=10)])
    assert _post(server, batch)[0] == 200
    status, body = _post(server, batch)
    assert status == 200 and body["status"] == "already_applied"

    status, body = _post(server, _batch("b1", metrics=[_metric(ts=100, value=11)]))
    assert status == 409 and body["code"] == "metric_batch_conflict"


def test_http_range_and_unresolved_statuses(server):
    status, body = _post(
        server,
        _batch("bad-range", metrics=[_metric(ts=9000)], max_event_time_ms=1000),
    )
    assert status == 400 and body["code"] == "metric_batch_range_invalid"

    plain = MetricStore()
    unresolved_server = _HTTPServer(plain)
    try:
        status, body = _post(
            unresolved_server,
            _batch("no-grid", metrics=[_metric()], downsample_ms=None),
        )
        assert status == 422 and body["code"] == "metric_window_unresolved"
    finally:
        unresolved_server.stop()


def test_http_malformed_json_and_unknown_route(server):
    req = urllib.request.Request(
        server.url("/batches"), data=b"{not json",
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=5)
    assert exc_info.value.code == 400

    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(server.url("/nope"), timeout=5)
    assert exc_info.value.code == 404
