"""Tests for deterministic recomputation of late-arriving metric samples."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from metric_fusion import BatchError, MetricBatchService
from metric_fusion.server import _make_handler


def sample(ts, source="a", name="cpu.usage", value=1.0, labels=None):
    return {
        "source": source,
        "name": name,
        "labels": {"host": "db-1"} if labels is None else labels,
        "timestamp_ms": ts,
        "value": value,
    }


def alert(alert_id, ts, source="a", name="cpu.usage", severity="warning", labels=None):
    return {
        "source": source,
        "name": name,
        "labels": {"host": "db-1"} if labels is None else labels,
        "alert_id": alert_id,
        "rule": "r1",
        "timestamp_ms": ts,
        "severity": severity,
    }


def make_service(**kwargs):
    kwargs.setdefault("downsample_ms", 1000)
    return MetricBatchService(**kwargs)


def base_batches():
    """Two timely batches seeding window 0 (value 1.0) and window 1000 (3.0)."""
    return [
        {
            "batch_id": "b1",
            "max_event_time_ms": 900,
            "metrics": [sample(100, value=1.0)],
        },
        {
            "batch_id": "b2",
            "max_event_time_ms": 1900,
            "metrics": [sample(1100, value=3.0)],
        },
    ]


def seed(service):
    for batch in base_batches():
        service.apply_batch(batch)


def seed_http(post):
    for batch in base_batches():
        status, _body = post("/v1/metric_batches", batch)
        assert status == 200


def window_rows(service, **query):
    return {
        (row["timestamp_ms"]): row
        for row in service.query_series(**query)
        if row["name"] == "cpu.usage"
    }


# -- recomputation of ended windows -------------------------------------------


def test_late_sample_recomputes_ended_window():
    service = make_service()
    seed(service)
    assert window_rows(service)[0]["value"] == 1.0

    result = service.submit_late_metrics({"metrics": [sample(200, value=5.0)]})
    assert result == {
        "accepted": 1,
        "duplicates": 0,
        "affected_streams": 1,
        "recomputed_windows": 1,
    }
    rows = window_rows(service)
    assert rows[0]["value"] == 3.0
    assert rows[0]["count"] == 2
    assert rows[0]["sources"] == ["a"]
    # The untouched window keeps its established result.
    assert rows[1000]["value"] == 3.0
    assert rows[1000]["count"] == 1
    # Repeated queries without new input return the same corrected values.
    assert service.query_series() == service.query_series()


def test_late_sample_is_not_a_new_series():
    service = make_service()
    seed(service)
    service.submit_late_metrics({"metrics": [sample(200, source="b", value=9.0)]})
    rows = window_rows(service)
    assert len(rows) == 2
    assert rows[0]["value"] == 5.0
    assert rows[0]["sources"] == ["a", "b"]


def test_multiple_late_timestamps_in_one_window_accumulate():
    service = make_service()
    seed(service)
    service.submit_late_metrics({"metrics": [sample(200, value=5.0)]})
    service.submit_late_metrics({"metrics": [sample(300, value=9.0)]})
    row = window_rows(service)[0]
    assert row["value"] == 5.0
    assert row["count"] == 3


def test_multiple_windows_accepted_in_any_order():
    def build(order):
        service = make_service()
        seed(service)
        for metrics in order:
            service.submit_late_metrics({"metrics": metrics})
        return service.query_series()

    late_a = [sample(200, value=5.0), sample(1200, value=7.0)]
    late_b = [sample(300, value=9.0)]
    forward = build([late_a, late_b])
    reverse = build([late_b, list(reversed(late_a))])
    combined = build([late_b + late_a])
    assert forward == reverse == combined
    rows = {row["timestamp_ms"]: row for row in forward}
    assert rows[0]["value"] == 5.0  # (1 + 5 + 9) / 3
    assert rows[1000]["value"] == 5.0  # (3 + 7) / 2


def test_late_samples_merge_with_batch_points_across_windows():
    service = make_service()
    seed(service)
    result = service.submit_late_metrics(
        {"metrics": [sample(200, value=5.0), sample(1200, value=7.0)]}
    )
    assert result["accepted"] == 2
    assert result["recomputed_windows"] == 2
    assert result["affected_streams"] == 1


# -- idempotency and conflicts ---------------------------------------------------


def test_identical_resubmission_is_idempotent():
    service = make_service()
    seed(service)
    first = service.submit_late_metrics({"metrics": [sample(200, value=5.0)]})
    assert first["accepted"] == 1
    before = service.query_series()
    second = service.submit_late_metrics({"metrics": [sample(200, value=5.0)]})
    assert second == {
        "accepted": 0,
        "duplicates": 1,
        "affected_streams": 0,
        "recomputed_windows": 0,
    }
    assert service.query_series() == before


def test_duplicate_within_one_request_counts_once():
    service = make_service()
    seed(service)
    result = service.submit_late_metrics(
        {"metrics": [sample(200, value=5.0), sample(200, value=5.0)]}
    )
    assert result["accepted"] == 1
    assert result["duplicates"] == 1
    assert window_rows(service)[0]["count"] == 2


def test_resubmission_of_already_stored_point_is_a_noop():
    service = make_service()
    seed(service)
    result = service.submit_late_metrics({"metrics": [sample(100, value=1.0)]})
    assert result["accepted"] == 0
    assert result["duplicates"] == 1
    assert window_rows(service)[0]["value"] == 1.0


def test_conflicting_value_against_stored_point_is_rejected():
    service = make_service()
    seed(service)
    with pytest.raises(BatchError) as excinfo:
        service.submit_late_metrics({"metrics": [sample(100, value=2.0)]})
    assert excinfo.value.status == 400
    assert excinfo.value.code == "late_metric_conflict"
    # The established window result is not rewritten.
    assert window_rows(service)[0]["value"] == 1.0


def test_conflicting_value_against_late_point_is_rejected():
    service = make_service()
    seed(service)
    service.submit_late_metrics({"metrics": [sample(200, value=5.0)]})
    with pytest.raises(BatchError) as excinfo:
        service.submit_late_metrics({"metrics": [sample(200, value=6.0)]})
    assert excinfo.value.status == 400
    assert excinfo.value.code == "late_metric_conflict"
    assert window_rows(service)[0]["value"] == 3.0


def test_conflict_within_one_request_is_rejected_atomically():
    service = make_service()
    seed(service)
    with pytest.raises(BatchError) as excinfo:
        service.submit_late_metrics(
            {"metrics": [sample(200, value=5.0), sample(200, value=9.0)]}
        )
    assert excinfo.value.status == 400
    assert excinfo.value.code == "late_metric_conflict"
    assert window_rows(service)[0]["count"] == 1


def test_conflict_anywhere_rejects_the_whole_request():
    service = make_service()
    seed(service)
    with pytest.raises(BatchError):
        service.submit_late_metrics(
            {"metrics": [sample(200, value=5.0), sample(100, value=2.0)]}
        )
    # The valid sample in the same request is not applied either.
    assert window_rows(service)[0]["count"] == 1


# -- timestamp validation --------------------------------------------------------


@pytest.mark.parametrize("timestamp", [None, "100", [100], float("nan"), float("inf"), -1])
def test_missing_or_unparseable_timestamp_is_rejected(timestamp):
    service = make_service()
    seed(service)
    bad = sample(0)
    if timestamp is None:
        del bad["timestamp_ms"]
    else:
        bad["timestamp_ms"] = timestamp
    with pytest.raises(BatchError) as excinfo:
        service.submit_late_metrics({"metrics": [bad]})
    assert excinfo.value.status == 400
    assert excinfo.value.code == "late_metric_invalid"
    assert window_rows(service)[0]["value"] == 1.0


@pytest.mark.parametrize(
    "raw",
    [None, "x", [{"source": "a"}], [sample(100, value="big")], [sample(100, name="")]],
)
def test_invalid_samples_are_rejected(raw):
    service = make_service()
    seed(service)
    with pytest.raises(BatchError) as excinfo:
        service.submit_late_metrics({"metrics": raw} if isinstance(raw, list) else raw)
    assert excinfo.value.status == 400
    assert excinfo.value.code == "late_metric_invalid"


def test_service_without_downsample_cannot_place_samples():
    service = MetricBatchService()
    with pytest.raises(BatchError) as excinfo:
        service.submit_late_metrics({"metrics": [sample(100)]})
    assert excinfo.value.status == 422
    assert excinfo.value.code == "metric_window_unresolved"


# -- retention range --------------------------------------------------------------


def test_empty_service_has_no_retained_window():
    service = make_service()
    with pytest.raises(BatchError) as excinfo:
        service.submit_late_metrics({"metrics": [sample(100)]})
    assert excinfo.value.status == 404
    assert excinfo.value.code == "late_metric_out_of_retention"


@pytest.mark.parametrize("timestamp", [999, 2000, 5000])
def test_timestamp_outside_retained_range_is_not_found(timestamp):
    service = make_service()
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 1900,
            "metrics": [sample(1100)],
        }
    )
    with pytest.raises(BatchError) as excinfo:
        service.submit_late_metrics({"metrics": [sample(timestamp)]})
    assert excinfo.value.status == 404
    assert excinfo.value.code == "late_metric_out_of_retention"
    assert len(service.query_series()) == 1


@pytest.mark.parametrize("timestamp", [1000, 1999])
def test_timestamp_inside_retained_range_is_accepted(timestamp):
    service = make_service()
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 1900,
            "metrics": [sample(1100)],
        }
    )
    result = service.submit_late_metrics({"metrics": [sample(timestamp)]})
    assert result["accepted"] == 1


def test_out_of_retention_anywhere_rejects_the_whole_request():
    service = make_service()
    seed(service)
    with pytest.raises(BatchError) as excinfo:
        service.submit_late_metrics(
            {"metrics": [sample(200, value=5.0), sample(9000, value=1.0)]}
        )
    assert excinfo.value.status == 404
    assert window_rows(service)[0]["count"] == 1


def test_late_samples_do_not_extend_the_retained_range():
    service = make_service()
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 1900,
            "metrics": [sample(1100)],
        }
    )
    service.submit_late_metrics({"metrics": [sample(1500)]})
    with pytest.raises(BatchError) as excinfo:
        service.submit_late_metrics({"metrics": [sample(2000)]})
    assert excinfo.value.status == 404


# -- alert re-evaluation ------------------------------------------------------------


def test_alert_adjudication_is_reevaluated_after_recompute():
    service = make_service(suppression_ms=10000)
    batches = base_batches()
    batches[1]["alerts"] = [alert("a1", 100), alert("a2", 200)]
    for batch in batches:
        service.apply_batch(batch)
    assert service.query_alerts()["suppressed_alert_ids"] == ["a2"]
    service.submit_late_metrics({"metrics": [sample(300, value=9.0)]})
    # Still matching the suppression conditions: the verdict stays suppressed.
    assert service.query_alerts()["suppressed_alert_ids"] == ["a2"]
    # Idempotent resubmission does not produce new alerts either.
    service.submit_late_metrics({"metrics": [sample(300, value=9.0)]})
    assert service.query_alerts()["suppressed_alert_ids"] == ["a2"]


def test_late_samples_drive_window_suppression_rules():
    service = make_service(
        window_suppression_rules=[
            {
                "rule_id": "cpu-flap",
                "source": "a",
                "metric": "cpu.usage",
                "pending_ms": 500,
                "suppression_ms": 1000,
                "recovery_ms": 100,
            }
        ]
    )
    service.apply_batch(
        {
            "batch_id": "b1",
            "max_event_time_ms": 1900,
            "metrics": [sample(1100), sample(1400)],
        }
    )
    (state,) = service.query_suppression_states()
    assert state["status"] == "pending"
    assert state["suppression_end_ms"] is None

    service.submit_late_metrics({"metrics": [sample(1600)]})
    (state,) = service.query_suppression_states()
    assert state["status"] == "suppressed"
    assert state["suppression_end_ms"] == 2600

    # An alert evaluated afterwards is adjudicated against the corrected state.
    service.apply_batch(
        {
            "batch_id": "b2",
            "max_event_time_ms": 1700,
            "metrics": [],
            "alerts": [alert("a1", 1700)],
        }
    )
    assert service.query_alerts()["suppressed_alert_ids"] == ["a1"]


# -- interplay with batches ---------------------------------------------------------


def test_retraction_keeps_late_points():
    service = make_service()
    seed(service)
    service.submit_late_metrics({"metrics": [sample(200, value=5.0)]})
    service.retract_batch("b1")
    rows = window_rows(service)
    # The late point survives the retraction; the other batch's window is
    # untouched.
    assert len(rows) == 2
    assert rows[0]["value"] == 5.0
    assert rows[0]["count"] == 1
    assert rows[1000]["value"] == 3.0


def test_batch_rank_still_corrects_a_late_point():
    service = make_service()
    seed(service)
    service.submit_late_metrics({"metrics": [sample(200, value=5.0)]})
    service.apply_batch(
        {
            "batch_id": "b3",
            "max_event_time_ms": 200,
            "metrics": [sample(200, value=9.0)],
        }
    )
    assert window_rows(service)[0]["value"] == 5.0  # (1 + 9) / 2
    service.retract_batch("b3")
    assert window_rows(service)[0]["value"] == 3.0  # late value restored


def test_query_time_options_see_late_samples():
    service = make_service()
    seed(service)
    service.submit_late_metrics({"metrics": [sample(900, value=5.0)]})
    rows = service.query_series(
        aggregations={"cpu.usage": "sum"}, downsample_overrides={"cpu.usage": 500}
    )
    assert [(row["timestamp_ms"], row["value"]) for row in rows] == [
        (0, 1.0),
        (500, 5.0),
        (1000, 3.0),
    ]


def test_reset_clears_late_samples():
    service = make_service()
    seed(service)
    service.submit_late_metrics({"metrics": [sample(200, value=5.0)]})
    service.reset()
    assert service.query_series() == []
    with pytest.raises(BatchError) as excinfo:
        service.submit_late_metrics({"metrics": [sample(200, value=5.0)]})
    assert excinfo.value.status == 404


# -- HTTP ---------------------------------------------------------------------


@pytest.fixture
def http_service():
    service = MetricBatchService(downsample_ms=1000)
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), _make_handler(service, threading.Lock())
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def post(path, body):
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            base + path, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def get(path):
        with urllib.request.urlopen(base + path) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    yield service, post, get
    server.shutdown()
    server.server_close()
    thread.join()


def test_http_late_metrics_flow(http_service):
    _service, post, get = http_service
    status, _body = post("/v1/metric_batches", base_batches()[0])
    assert status == 200
    status, _body = post("/v1/metric_batches", base_batches()[1])
    assert status == 200
    status, body = post("/v1/late_metrics", {"metrics": [sample(200, value=5.0)]})
    assert status == 200
    assert body == {
        "accepted": 1,
        "duplicates": 0,
        "affected_streams": 1,
        "recomputed_windows": 1,
    }
    status, body = get("/v1/series")
    assert status == 200
    rows = {row["timestamp_ms"]: row for row in body["series"]}
    assert rows[0]["value"] == 3.0
    assert rows[1000]["value"] == 3.0
    # A bare list of samples is accepted too.
    status, body = post("/v1/late_metrics", [sample(300, value=9.0)])
    assert status == 200
    assert body["accepted"] == 1


def test_http_late_metrics_conflict_returns_400(http_service):
    _service, post, _get = http_service
    seed_http(post)
    status, body = post("/v1/late_metrics", {"metrics": [sample(100, value=2.0)]})
    assert status == 400
    assert body == {"code": "late_metric_conflict", "message": "late metric conflict"}


def test_http_late_metrics_invalid_timestamp_returns_400(http_service):
    _service, post, _get = http_service
    seed_http(post)
    status, body = post("/v1/late_metrics", {"metrics": [sample("soon")]})
    assert status == 400
    assert body == {"code": "late_metric_invalid", "message": "invalid timestamp"}


def test_http_late_metrics_out_of_retention_returns_404(http_service):
    _service, post, _get = http_service
    seed_http(post)
    status, body = post("/v1/late_metrics", {"metrics": [sample(9000)]})
    assert status == 404
    assert body == {
        "code": "late_metric_out_of_retention",
        "message": "late metric out of retention",
    }
