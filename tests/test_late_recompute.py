"""Tests for deterministic late-data recompute (POST /v1/recompute)."""

import json
import threading
from http.server import ThreadingHTTPServer
from urllib import error as urllib_error
from urllib import request as urllib_request

import pytest

from metric_fusion import MetricBatchService, RecomputeError
from metric_fusion.server import _make_handler

NOW = 100_000
RETENTION = 50_000  # accepted sampling times: [50_000, 100_000]
DS = 1000


def make_service(**overrides):
    kwargs = {
        "downsample_ms": DS,
        "clock_ms": NOW,
        "retention_ms": RETENTION,
    }
    kwargs.update(overrides)
    return MetricBatchService(**kwargs)


def point(ts, value=1.0, source="s", name="m", labels=None, event_id=None, **extra):
    raw = {
        "source": source,
        "name": name,
        "labels": {"host": "a"} if labels is None else labels,
        "timestamp_ms": ts,
        "value": value,
    }
    if event_id is not None:
        raw["event_id"] = event_id
    raw.update(extra)
    return raw


def recompute(request_id, points, **extra):
    body = {"request_id": request_id, "points": points}
    body.update(extra)
    return body


def seed_batch(service, batch_id="online-1", max_event_time_ms=50_900, metrics=None):
    # Both default samples share the DS bucket [50_000, 51_000), which is also
    # the single batch window apply_batch requires.
    if metrics is None:
        metrics = [point(50_000, 10.0), point(50_500, 20.0)]
    return service.apply_batch(
        {
            "batch_id": batch_id,
            "max_event_time_ms": max_event_time_ms,
            "metrics": metrics,
        }
    )


# -- counts: accepted / duplicate / conflicting -------------------------------


def test_accepted_and_duplicate_points():
    service = make_service()
    result = service.recompute(
        recompute(
            "r1",
            [
                point(50_000, 1.0),
                point(50_500, 2.0),
                point(51_000, 3.0, labels={"host": "b"}),
                # exact logical repeats (same source/name/labels/timestamp)...
                point(50_000, 1.0),
                point(50_500, 2.0),
            ],
        )
    )
    assert result["accepted_points"] == 3
    assert result["duplicate_points"] == 2
    assert result["request_id"] == "r1"


def test_conflicting_duplicate_value_writes_nothing():
    service = make_service()
    # Both online samples fall in bucket [50_000, 51_000): average 15.0.
    seed_batch(service, metrics=[point(50_000, 10.0), point(50_500, 20.0)])
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute(
            recompute("r1", [point(50_000, 1.0), point(50_000, 9.0)])
        )
    assert excinfo.value.status == 400
    assert excinfo.value.error == "conflicting_duplicate"
    assert excinfo.value.request_id == "r1"
    # Nothing was written: series still reflects only the online batch.
    rows = service.query_series()
    assert [(r["timestamp_ms"], r["value"]) for r in rows] == [
        (50_000, 15.0)
    ]
    # The failed request_id is not cached and can be retried successfully.
    ok = service.recompute(recompute("r1", [point(50_000, 1.0)]))
    assert ok["accepted_points"] == 1


def test_conflicting_duplicate_tags_in_either_order():
    service = make_service()
    seed_batch(service)
    variants = [
        point(50_000, 1.0, labels={"host": "a"}),
        point(50_000, 1.0, labels={"host": "b"}),
    ]
    for order in (variants, list(reversed(variants))):
        request_id = "tag-" + str(order[0]["labels"])
        with pytest.raises(RecomputeError) as excinfo:
            service.recompute(recompute(request_id, order))
        assert excinfo.value.error == "conflicting_duplicate"
    # Semantically identical tag sets in a different insertion order are not a
    # conflict: canonicalization makes them the same logical point.
    result = service.recompute(
        recompute(
            "tag-ok",
            [
                point(50_100, 1.0, labels={"a": "1", "b": "2"}),
                point(50_100, 1.0, labels={"b": "2", "a": "1"}),
            ],
        )
    )
    assert result["accepted_points"] == 1
    assert result["duplicate_points"] == 1


def test_cross_request_conflicting_value_writes_nothing():
    service = make_service()
    seed_batch(service, metrics=[point(50_000, 10.0)])
    first = service.recompute(recompute("r1", [point(50_000, 30.0)]))
    assert first["recomputed_buckets"] == 1
    assert service.query_series()[0]["value"] == 30.0
    # The same late identity arriving in another request with a different
    # value is a deterministic conflict and must not rewrite the window.
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute(recompute("r2", [point(50_000, 99.0)]))
    assert excinfo.value.status == 400
    assert excinfo.value.error == "conflicting_duplicate"
    assert excinfo.value.request_id == "r2"
    rows = service.query_series()
    assert [(r["timestamp_ms"], r["value"]) for r in rows] == [(50_000, 30.0)]
    # The rejected request is not cached: the same request_id can succeed once
    # it carries the established value.
    ok = service.recompute(recompute("r2", [point(50_000, 30.0)]))
    assert ok["accepted_points"] == 1
    # Nothing changed: the established late value is already the winner.
    assert ok["recomputed_buckets"] == 0


def test_cross_request_conflicting_tags_writes_nothing():
    service = make_service()
    service.recompute(recompute("r1", [point(50_000, 1.0, labels={"host": "a"})]))
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute(
            recompute("r2", [point(50_000, 1.0, labels={"host": "b"})])
        )
    assert excinfo.value.error == "conflicting_duplicate"
    by_labels = {
        tuple(sorted(r["labels"].items())): r["value"]
        for r in service.query_series()
    }
    assert by_labels == {(("host", "a"),): 1.0}


def test_cross_request_identical_late_point_is_idempotent():
    service = make_service()
    seed_batch(service, metrics=[point(50_000, 10.0)])
    first = service.recompute(recompute("r1", [point(50_000, 30.0)]))
    second = service.recompute(recompute("r2", [point(50_000, 30.0)]))
    assert second["recomputed_buckets"] == 0
    assert service.query_series()[0]["value"] == 30.0
    assert first["request_id"] == "r1"


# -- validation errors ---------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        "nope",
        {"points": []},  # missing request_id
        {"request_id": "", "points": []},
        {"request_id": 7, "points": []},
        {"request_id": "r1"},  # missing points
        {"request_id": "r1", "points": {}},
        {"request_id": "r1", "points": ["x"]},
        {"request_id": "r1", "points": [point(50_000, source="")]},
        {"request_id": "r1", "points": [point(50_000, name="")]},
        {"request_id": "r1", "points": [point(None)]},
        {"request_id": "r1", "points": [point("soon")]},
        {"request_id": "r1", "points": [point(-1)]},
        {"request_id": "r1", "points": [point(50_000, event_id="")]},
        {"request_id": "r1", "points": [point(50_000, event_id=5)]},
    ],
)
def test_invalid_recompute_request(body):
    service = make_service()
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute(body)
    assert excinfo.value.status == 400
    assert excinfo.value.error == "invalid_recompute_request"


def test_missing_request_id_error_carries_null_request_id():
    service = make_service()
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute({"points": [point(50_000)]})
    assert excinfo.value.request_id is None


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), -float("inf"), "1", None, True])
def test_invalid_value(bad_value):
    service = make_service()
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute(recompute("r1", [point(50_000, bad_value)]))
    assert excinfo.value.status == 400
    assert excinfo.value.error == "invalid_value"
    assert excinfo.value.request_id == "r1"


@pytest.mark.parametrize("bad_labels", ["x", ["x"], 5])
def test_invalid_tags(bad_labels):
    service = make_service()
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute(recompute("r1", [point(50_000, labels=bad_labels)]))
    assert excinfo.value.status == 400
    assert excinfo.value.error == "invalid_tags"


def test_missing_labels_is_invalid_tags():
    service = make_service()
    raw = point(50_000)
    del raw["labels"]  # absent, not merely the helper default
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute(recompute("r1", [raw]))
    assert excinfo.value.error == "invalid_tags"
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute(recompute("r2", [{**point(50_000), "labels": None}]))
    assert excinfo.value.error == "invalid_tags"


def test_outside_retention_is_404_and_boundaries():
    service = make_service()
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute(recompute("r1", [point(49_999)]))
    assert excinfo.value.status == 404
    assert excinfo.value.error == "outside_retention"
    assert excinfo.value.request_id == "r1"
    # Boundaries are inclusive on both sides: exactly at the retention edge
    # and exactly at reception time are accepted.
    assert service.recompute(recompute("r2", [point(50_000)]))["accepted_points"] == 1
    assert service.recompute(recompute("r3", [point(NOW)]))["accepted_points"] == 1


def test_outside_retention_changes_nothing():
    service = make_service()
    seed_batch(service)
    before = service.query_series()
    with pytest.raises(RecomputeError):
        service.recompute(
            recompute(
                "r1",
                [
                    point(50_000, 1.0),
                    point(100, 1.0),  # far outside retention: whole request rejected
                ],
            )
        )
    assert service.query_series() == before


def test_future_timestamp():
    service = make_service()
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute(recompute("r1", [point(NOW + 1)]))
    assert excinfo.value.status == 400
    assert excinfo.value.error == "future_timestamp"


def test_downsample_ms_unconfigured_rejects_points():
    service = MetricBatchService(downsample_ms=None, clock_ms=NOW)
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute(recompute("r1", [point(50_000)]))
    assert excinfo.value.error == "invalid_recompute_request"
    # An empty batch is valid even without a configured window size.
    empty = service.recompute(recompute("r2", []))
    assert empty["accepted_points"] == 0
    assert empty["recomputed_buckets"] == 0
    assert empty["affected_ranges"] == []


def test_invalid_batch_changes_nothing():
    service = make_service()
    seed_batch(service)
    before = service.query_series()
    with pytest.raises(RecomputeError):
        service.recompute(
            recompute(
                "r1",
                [
                    point(50_000, 1.0),
                    point(200_000, 1.0),  # future: whole batch rejected
                ],
            )
        )
    assert service.query_series() == before


# -- idempotency ----------------------------------------------------------------


def test_replay_returns_original_result_without_changes():
    service = make_service()
    body = recompute("r1", [point(50_000, 30.0), point(50_000, 30.0)])
    first = service.recompute(body)
    second = service.recompute(body)
    third = service.recompute(body)
    assert first == second == third
    assert first["accepted_points"] == 1
    assert first["duplicate_points"] == 1
    # Mutating a returned result does not poison the cached replay.
    first["affected_ranges"].append("tampered")
    assert service.recompute(body)["affected_ranges"] == second["affected_ranges"]


def test_replay_with_shuffled_order_is_identical():
    service = make_service()
    pts = [point(50_000, 1.0), point(51_000, 2.0), point(52_000, 3.0)]
    first = service.recompute(recompute("r1", pts))
    second = service.recompute(recompute("r1", list(reversed(pts))))
    assert first == second


def test_same_request_id_with_different_content_conflicts():
    service = make_service()
    service.recompute(recompute("r1", [point(50_000, 1.0)]))
    with pytest.raises(RecomputeError) as excinfo:
        service.recompute(recompute("r1", [point(50_000, 2.0)]))
    assert excinfo.value.status == 409
    assert excinfo.value.error == "recompute_conflict"


def test_replayed_request_skips_retention_and_future_validation():
    # After the point has aged out of retention the replay is still served from
    # the original result: no error, no mutation.
    current = {"now": 50_000}
    service = MetricBatchService(
        downsample_ms=DS,
        retention_ms=1_000,  # at submission, 50_000 lies in [49_000, 50_000]
        clock_ms=lambda: current["now"],
    )
    body = recompute("old", [point(50_000, 1.0)])
    first = service.recompute(body)
    assert first["accepted_points"] == 1
    current["now"] = 200_000  # the point is now far outside retention
    replay = service.recompute(body)
    # The cached original result is returned verbatim even though the same
    # point would now be rejected as outside_retention; nothing re-applied.
    assert replay == first


# -- bucket recomputation & affected ranges ------------------------------------


def test_late_point_overwrites_only_its_own_window():
    service = make_service()
    seed_batch(
        service,
        max_event_time_ms=50_900,
        metrics=[point(50_000, 10.0), point(50_500, 20.0)],
    )
    assert service.query_series()[0]["value"] == 15.0  # bucket 50_000

    result = service.recompute(recompute("r1", [point(50_000, 30.0)]))
    # The late point wins over the online sample in bucket 50_000 only.
    assert result["recomputed_buckets"] == 1
    assert result["affected_ranges"] == [
        {"name": "m", "labels": {"host": "a"}, "start_ms": 50_000, "end_ms": 51_000}
    ]
    rows = service.query_series()
    assert [(r["timestamp_ms"], r["value"]) for r in rows] == [(50_000, 25.0)]

    # A later window is left untouched by a correction elsewhere.
    service.apply_batch(
        {
            "batch_id": "online-2",
            "max_event_time_ms": 52_900,
            "metrics": [point(52_000, 40.0), point(52_500, 40.0)],
        }
    )
    result = service.recompute(recompute("r2", [point(52_000, 80.0)]))
    assert result["recomputed_buckets"] == 1
    assert result["affected_ranges"][0]["start_ms"] == 52_000
    by_start = {r["timestamp_ms"]: r["value"] for r in service.query_series()}
    assert by_start[50_000] == 25.0  # earlier window untouched
    assert by_start[52_000] == 60.0  # (80 + 40) / 2


def test_several_timestamps_in_one_window_are_kept_and_reaggregated():
    service = make_service()
    seed_batch(service, metrics=[point(50_000, 10.0)])
    # Two late points at distinct timestamps of the same window accumulate.
    service.recompute(recompute("r1", [point(50_200, 20.0)]))
    result = service.recompute(recompute("r2", [point(50_800, 30.0)]))
    assert result["recomputed_buckets"] == 1
    rows = service.query_series()
    assert [(r["timestamp_ms"], r["value"], r["count"]) for r in rows] == [
        (50_000, 20.0, 3),
    ]
    assert rows[0]["sources"] == ["s"]


def test_missing_late_sample_fills_window():
    service = make_service()
    seed_batch(
        service,
        max_event_time_ms=50_900,
        metrics=[point(50_000, 10.0)],
    )
    result = service.recompute(recompute("r1", [point(50_500, 30.0)]))
    assert result["recomputed_buckets"] == 1
    assert service.query_series()[0]["value"] == 20.0  # (10 + 30) / 2


def test_noop_correction_counts_no_buckets_or_ranges():
    service = make_service()
    seed_batch(service, metrics=[point(50_000, 10.0)])
    # Same value as the current winner: the merged window is unchanged.
    result = service.recompute(
        recompute("r1", [point(50_000, 10.0)])
    )
    assert result["recomputed_buckets"] == 0
    assert result["affected_ranges"] == []


def test_adjacent_changed_buckets_merge_into_one_range():
    service = make_service()
    seed_batch(service)
    result = service.recompute(
        recompute(
            "r1",
            [
                point(50_000, 100.0),  # bucket 50_000
                point(51_000, 100.0),  # bucket 51_000, adjacent
            ],
        )
    )
    assert result["recomputed_buckets"] == 2
    assert result["affected_ranges"] == [
        {"name": "m", "labels": {"host": "a"}, "start_ms": 50_000, "end_ms": 52_000}
    ]


def test_non_adjacent_buckets_and_series_produce_separate_ranges():
    service = make_service()
    seed_batch(service)
    result = service.recompute(
        recompute(
            "r1",
            [
                point(50_000, 100.0),  # bucket 50_000
                point(52_000, 100.0),  # bucket 52_000: gap at 51_000
                point(52_500, 100.0, name="other"),
            ],
        )
    )
    ranges = result["affected_ranges"]
    assert ranges == [
        {"name": "m", "labels": {"host": "a"}, "start_ms": 50_000, "end_ms": 51_000},
        {"name": "m", "labels": {"host": "a"}, "start_ms": 52_000, "end_ms": 53_000},
        {"name": "other", "labels": {"host": "a"}, "start_ms": 52_000, "end_ms": 53_000},
    ]


def test_late_point_outranks_online_batches_and_survives_retraction():
    service = make_service()
    seed_batch(service, metrics=[point(50_000, 10.0)])
    service.recompute(recompute("fix", [point(50_000, 40.0)]))
    assert service.query_series()[0]["value"] == 40.0
    # Retracting the online batch must not remove the late correction.
    retracted = service.retract_batch("online-1")
    assert retracted["recomputed_windows"] == 0
    assert service.query_series()[0]["value"] == 40.0


def test_arrival_order_does_not_change_final_series():
    # Windows accepted in any order converge to the same corrected series.
    def run(order):
        service = make_service()
        seed_batch(
            service,
            batch_id="online-1",
            metrics=[point(50_000, 10.0)],
            max_event_time_ms=50_900,
        )
        service.apply_batch(
            {
                "batch_id": "online-2",
                "max_event_time_ms": 51_900,
                "metrics": [point(51_000, 10.0)],
            }
        )
        late = [
            ("r1", [point(50_500, 30.0)]),
            ("r2", [point(51_500, 70.0)]),
        ]
        for request_id, points in late[::order]:
            service.recompute(recompute(request_id, points))
        return service.query_series()

    assert [(r["timestamp_ms"], r["value"]) for r in run(1)] == [
        (50_000, 20.0),
        (51_000, 40.0),
    ]
    assert run(1) == run(-1)


# -- notifications / suppression ------------------------------------------------


def test_event_points_produce_notifications():
    service = make_service()
    result = service.recompute(
        recompute(
            "r1",
            [
                point(50_000, 1.0, event_id="e2"),
                point(50_500, 2.0),  # no event id: aggregate-only point
                point(50_100, 3.0, event_id="e1"),
            ],
        )
    )
    assert [n["event_id"] for n in result["notifications"]] == ["e2", "e1"]
    assert result["suppressed_notifications"] == []
    notified = result["notifications"][0]
    assert notified == point(50_000, 1.0, event_id="e2")


def test_duplicate_event_does_not_notify_again():
    service = make_service()
    first = service.recompute(recompute("r1", [point(50_000, 1.0, event_id="e1")]))
    assert [n["event_id"] for n in first["notifications"]] == ["e1"]
    # Resubmitting the same late event (different request) neither recounts
    # nor raises a second notification.
    second = service.recompute(recompute("r2", [point(50_000, 1.0, event_id="e1")]))
    assert second["notifications"] == []
    assert second["suppressed_notifications"] == []
    assert second["recomputed_buckets"] == 0


def test_maintenance_window_suppresses_event_notification():
    service = make_service(
        maintenance_windows=[
            {
                "window_id": "w1",
                "start_ms": 40_000,
                "end_ms": 60_000,
                "name": "m",
            }
        ]
    )
    result = service.recompute(
        recompute(
            "r1",
            [
                point(50_000, 1.0, event_id="in"),
                point(70_000, 1.0, event_id="out"),
            ],
        )
    )
    assert [n["event_id"] for n in result["notifications"]] == ["out"]
    assert [n["event_id"] for n in result["suppressed_notifications"]] == ["in"]


def test_window_rule_state_suppresses_late_event():
    service = make_service(
        window_suppression_rules=[
            {
                "rule_id": "rule-1",
                "source": "s",
                "metric": "m",
                "labels": {},
                "pending_ms": 0,
                "suppression_ms": 100_000,
                "recovery_ms": 0,
            }
        ]
    )
    # Online intake establishes the suppression episode.
    seed_batch(service, metrics=[point(50_000, 1.0)])
    result = service.recompute(
        recompute("r1", [point(51_000, 2.0, event_id="late")])
    )
    assert result["notifications"] == []
    assert [n["event_id"] for n in result["suppressed_notifications"]] == ["late"]


def test_confirmed_suppression_is_sticky():
    service = make_service(
        maintenance_windows=[
            {"window_id": "w1", "start_ms": 40_000, "end_ms": 60_000, "name": "m"}
        ]
    )
    first = service.recompute(
        recompute("r1", [point(50_000, 1.0, event_id="e1")])
    )
    assert [n["event_id"] for n in first["suppressed_notifications"]] == ["e1"]

    # Lift the suppression configuration, then re-submit the same event: the
    # already-confirmed suppression is not released by the duplicate event.
    service.set_maintenance_windows([])
    again = service.recompute(
        recompute("r2", [point(50_000, 1.0, event_id="e1")])
    )
    assert again["notifications"] == []
    assert [n["event_id"] for n in again["suppressed_notifications"]] == ["e1"]


# -- determinism ----------------------------------------------------------------


def test_same_inputs_same_history_identical_result():
    def run(order):
        service = make_service()
        seed_batch(service)
        pts = [
            point(50_000, 100.0, event_id="e1"),
            point(51_200, 5.0, labels={"host": "z"}),
            point(50_500, 7.0, event_id="e2"),
        ]
        return service.recompute(recompute("r1", pts[::order]))

    forward = run(1)
    reverse = run(-1)
    assert forward == reverse
    # JSON-serializable and stable across serialization.
    assert json.loads(json.dumps(forward)) == forward


# -- HTTP -----------------------------------------------------------------------


@pytest.fixture
def http_service():
    service = make_service()
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), _make_handler(service, threading.Lock())
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def post(path, body, raw=False):
        data = body if raw else json.dumps(body).encode("utf-8")
        req = urllib_request.Request(
            base + path, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib_request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib_error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    yield service, post
    server.shutdown()
    server.server_close()
    thread.join()


def test_http_recompute_success_shape(http_service):
    _service, post = http_service
    status, body = post(
        "/v1/recompute",
        recompute("req-1", [point(50_000, 1.0), point(50_000, 1.0)]),
    )
    assert status == 200
    assert set(body) == {
        "request_id",
        "accepted_points",
        "duplicate_points",
        "recomputed_buckets",
        "notifications",
        "suppressed_notifications",
        "affected_ranges",
    }
    assert body["request_id"] == "req-1"
    assert body["accepted_points"] == 1
    assert body["duplicate_points"] == 1


@pytest.mark.parametrize(
    "body,expected_status,expected_error",
    [
        (recompute("r1", [point(200_000, 1.0)]), 400, "future_timestamp"),
        (recompute("r1", [point(50_000, float("nan"))]), 400, "invalid_value"),
        (recompute("r1", [point(50_000, labels="x")]), 400, "invalid_tags"),
        (recompute("r1", [point(100, 1.0)]), 404, "outside_retention"),
        (recompute("r1", [point(50_000, 1.0), point(50_000, 2.0)]),
         400, "conflicting_duplicate"),
        ({"points": []}, 400, "invalid_recompute_request"),
    ],
)
def test_http_recompute_error_envelope(http_service, body, expected_status, expected_error):
    _service, post = http_service
    status, payload = post("/v1/recompute", body)
    assert status == expected_status
    request_id = body.get("request_id") if isinstance(body, dict) else None
    assert payload == {
        "status": expected_status,
        "error": expected_error,
        "request_id": request_id,
    }


def test_http_recompute_invalid_json_envelope(http_service):
    _service, post = http_service
    status, payload = post("/v1/recompute", b"{not json", raw=True)
    assert status == 400
    assert payload == {
        "status": 400,
        "error": "invalid_recompute_request",
        "request_id": None,
    }


def test_http_recompute_replay_is_idempotent(http_service):
    _service, post = http_service
    body = recompute("r1", [point(50_000, 1.0)])
    status1, first = post("/v1/recompute", body)
    status2, second = post("/v1/recompute", body)
    assert (status1, status2) == (200, 200)
    assert first == second


def test_http_other_endpoints_keep_legacy_error_envelope(http_service):
    _service, post = http_service
    # Existing endpoints must keep the {"code", "message"} shape.
    status, payload = post("/v1/query", {"aggregations": {"m": "nope"}})
    assert status == 400
    assert set(payload) == {"code", "message"}
    assert payload["code"] == "invalid_request"


def test_http_unknown_path_still_404(http_service):
    _service, post = http_service
    status, payload = post("/v1/nope", {})
    assert status == 404
    assert payload == {"code": "not_found", "message": "not found"}
