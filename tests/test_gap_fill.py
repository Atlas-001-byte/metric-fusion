"""Tests for optional gap_fill window completion."""

import json
import threading
from http.server import ThreadingHTTPServer
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from metric_fusion.server import _make_handler
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


# -- process() ----------------------------------------------------------------


def test_fill_between_adjacent_windows_carries_value():
    result = process(
        payload(
            [sample(0, value=3.0), sample(3000, value=7.0)],
            gap_fill={"cpu.usage": 2000},
        )
    )
    rows = result["series"]
    assert [row["timestamp_ms"] for row in rows] == [0, 1000, 2000, 3000]
    assert rows[0]["value"] == 3.0
    assert rows[1] == {
        "name": "cpu.usage",
        "labels": {"host": "db-1"},
        "timestamp_ms": 1000,
        "value": 3.0,
        "count": 0,
        "sources": [],
    }
    assert rows[2]["value"] == 3.0
    assert rows[2]["count"] == 0
    assert rows[2]["sources"] == []
    assert rows[3]["value"] == 7.0
    assert rows[3]["count"] == 1


def test_fill_boundary_is_inclusive():
    # Two windows apart by one downsample step: missing span is exactly
    # downsample_ms, so max_gap_ms == downsample_ms fills; one less does not.
    filled = process(
        payload([sample(0), sample(2000)], gap_fill={"cpu.usage": 1000})
    )
    assert [row["timestamp_ms"] for row in filled["series"]] == [0, 1000, 2000]

    not_filled = process(
        payload([sample(0), sample(2000)], gap_fill={"cpu.usage": 999})
    )
    assert [row["timestamp_ms"] for row in not_filled["series"]] == [0, 2000]


def test_gap_over_limit_is_not_filled():
    # Missing span between 0 and 5000 is 4000ms.
    result = process(
        payload([sample(0), sample(5000)], gap_fill={"cpu.usage": 3000})
    )
    assert [row["timestamp_ms"] for row in result["series"]] == [0, 5000]

    result = process(
        payload([sample(0), sample(5000)], gap_fill={"cpu.usage": 4000})
    )
    assert [row["timestamp_ms"] for row in result["series"]] == [
        0, 1000, 2000, 3000, 4000, 5000
    ]


def test_no_fill_before_first_or_after_last_window():
    result = process(
        payload([sample(2000), sample(3000)], gap_fill={"cpu.usage": 100000})
    )
    assert [row["timestamp_ms"] for row in result["series"]] == [2000, 3000]


def test_unconfigured_metric_is_not_filled():
    result = process(
        payload(
            [sample(0, name="cpu.usage"), sample(3000, name="cpu.usage"),
             sample(0, name="mem.usage"), sample(3000, name="mem.usage")],
            gap_fill={"cpu.usage": 5000},
        )
    )
    assert [
        (row["name"], row["timestamp_ms"]) for row in result["series"]
    ] == [
        ("cpu.usage", 0), ("cpu.usage", 1000), ("cpu.usage", 2000),
        ("cpu.usage", 3000),
        ("mem.usage", 0), ("mem.usage", 3000),
    ]


def test_fill_is_scoped_per_normalized_series():
    result = process(
        payload(
            [
                sample(0, labels={"host": "db-1"}),
                sample(3000, labels={"host": "db-1"}),
                sample(0, labels={"host": "db-2"}),
                sample(3000, labels={"host": "db-2"}),
            ],
            gap_fill={"cpu.usage": 5000},
        )
    )
    assert [
        (row["labels"]["host"], row["timestamp_ms"]) for row in result["series"]
    ] == [
        ("db-1", 0), ("db-1", 1000), ("db-1", 2000), ("db-1", 3000),
        ("db-2", 0), ("db-2", 1000), ("db-2", 2000), ("db-2", 3000),
    ]


def test_quorum_denied_window_breaks_fill_chain():
    # Window 0 and 2000 pass quorum 2; window 1000 has one source and is
    # denied. It must neither be restored nor allow bridging 0 -> 2000.
    metrics = [
        sample(0, "a"), sample(100, "b"),
        sample(1000, "a"),
        sample(2000, "a"), sample(2100, "b"),
    ]
    result = process(
        payload(
            metrics,
            source_quorum={"cpu.usage": 2},
            gap_fill={"cpu.usage": 100000},
        )
    )
    assert [row["timestamp_ms"] for row in result["series"]] == [0, 2000]
    assert result["series"][0]["sources"] == ["a", "b"]


def test_fill_carries_aggregated_value_not_raw_samples():
    result = process(
        payload(
            [sample(0, value=3.0), sample(100, "b", value=5.0),
             sample(3000, value=9.0)],
            aggregations={"cpu.usage": "sum"},
            gap_fill={"cpu.usage": 5000},
        )
    )
    values = [(row["timestamp_ms"], row["value"]) for row in result["series"]]
    assert values == [(0, 8.0), (1000, 8.0), (2000, 8.0), (3000, 9.0)]


def test_fill_with_source_weights():
    result = process(
        payload(
            [sample(0, "a", value=4.0), sample(3000, "a", value=6.0)],
            source_weights={"cpu.usage": {"a": 2.0}},
            gap_fill={"cpu.usage": 5000},
        )
    )
    rows = result["series"]
    assert [row["timestamp_ms"] for row in rows] == [0, 1000, 2000, 3000]
    assert rows[1]["value"] == 4.0
    assert rows[1]["count"] == 0
    assert rows[1]["sources"] == []
    assert "weight_missing" not in rows[1]


def test_fill_with_source_priority():
    result = process(
        payload(
            [sample(0, "b", value=4.0), sample(3000, "b", value=6.0)],
            source_priority={"cpu.usage": ["a", "b"]},
            gap_fill={"cpu.usage": 5000},
        )
    )
    rows = result["series"]
    assert [row["timestamp_ms"] for row in rows] == [0, 1000, 2000, 3000]
    assert rows[1]["value"] == 4.0
    assert rows[1]["count"] == 0
    assert rows[1]["sources"] == []
    assert "priority_missing" not in rows[1]


def test_alerts_and_suppression_unaffected_by_gap_fill():
    alert = {
        "source": "a",
        "name": "cpu.usage",
        "labels": {"host": "db-1"},
        "alert_id": "a1",
        "rule": "cpu-high",
        "timestamp_ms": 1000,
        "severity": "warning",
    }
    request = payload([sample(0), sample(3000)], alerts=[alert])
    request["gap_fill"] = {"cpu.usage": 5000}
    result = process(request)
    assert result["alerts"] == [
        {"alert_id": "a1", "severity": "warning", "suppressed": False}
    ]
    assert result["suppressed_alert_ids"] == []
    assert set(result) == {"series", "alerts", "suppressed_alert_ids"}


def test_absent_gap_fill_matches_baseline_output():
    metrics = [sample(0), sample(3000)]
    assert process(payload(metrics))["series"] == process(
        payload(metrics, gap_fill={})
    )["series"]
    assert process(payload(metrics))["series"] == process(
        payload(metrics, gap_fill=None)
    )["series"]


@pytest.mark.parametrize(
    "raw",
    [
        "not-a-mapping",
        ["not-a-mapping"],
        {"": 1},
        {"cpu.usage": 0},
        {"cpu.usage": -1},
        {"cpu.usage": 1.5},
        {"cpu.usage": True},
        {"cpu.usage": False},
        {"cpu.usage": None},
        {"cpu.usage": "2"},
        {1: 1},
    ],
)
def test_invalid_gap_fill_in_process(raw):
    with pytest.raises(ValueError, match="^invalid gap_fill$"):
        process(payload([sample(0)], gap_fill=raw))


# -- MetricBatchService -------------------------------------------------------


def test_service_query_gap_fill():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, value=2.0)]}
    )
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 3900,
         "metrics": [sample(3000, value=8.0)]}
    )
    rows = service.query_series(gap_fill={"cpu.usage": 5000})
    assert [(r["timestamp_ms"], r["value"], r["count"], r["sources"]) for r in rows] == [
        (0, 2.0, 1, ["a"]),
        (1000, 2.0, 0, []),
        (2000, 2.0, 0, []),
        (3000, 8.0, 1, ["a"]),
    ]
    # Without the option the stored windows are queried as-is.
    assert [r["timestamp_ms"] for r in service.query_series()] == [0, 3000]


def test_service_gap_fill_recomputed_after_correction_and_retraction():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0)]}
    )
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 3900, "metrics": [sample(3000)]}
    )
    assert [r["timestamp_ms"] for r in service.query_series(gap_fill={"cpu.usage": 5000})] == [
        0, 1000, 2000, 3000
    ]

    # A late correction filling the middle removes the generated rows.
    service.apply_batch(
        {"batch_id": "b3", "max_event_time_ms": 1900, "metrics": [sample(1000)]}
    )
    rows = service.query_series(gap_fill={"cpu.usage": 5000})
    assert [(r["timestamp_ms"], r["count"]) for r in rows] == [
        (0, 1), (1000, 1), (2000, 0), (3000, 1)
    ]

    service.retract_batch("b3")
    assert [r["timestamp_ms"] for r in service.query_series(gap_fill={"cpu.usage": 5000})] == [
        0, 1000, 2000, 3000
    ]


def test_service_gap_fill_validation():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900, "metrics": [sample(0)]}
    )
    for raw in ({"x": 0}, {"x": True}, {"x": 1.5}, "nope", {"": 1}, {"x": -2}):
        with pytest.raises(ValueError, match="^invalid gap_fill$"):
            service.query_series(gap_fill=raw)
    # Stored state is untouched by a rejected query option.
    assert [r["timestamp_ms"] for r in service.query_series()] == [0]


def test_service_batch_responses_and_alerts_ignore_gap_fill():
    service = MetricBatchService(downsample_ms=1000)
    first = service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0)]}
    )
    assert first == {
        "batch_id": "b1",
        "status": "applied",
        "affected_streams": 1,
        "recomputed_windows": 1,
    }
    second = service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 3900,
         "metrics": [sample(3000)]}
    )
    assert second["affected_streams"] == 1
    assert second["recomputed_windows"] == 1
    alerts = service.query_alerts()
    assert alerts["suppressed_alert_ids"] == []
    assert "series" not in alerts


# -- HTTP ---------------------------------------------------------------------


class _HttpServer:
    def __init__(self, service):
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), _make_handler(service, threading.Lock())
        )
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()

    def post(self, path, payload):
        data = json.dumps(payload).encode("utf-8")
        req = urlrequest.Request(
            self.url + path, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urlrequest.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


@pytest.fixture()
def http_service():
    service = MetricBatchService(downsample_ms=1000)
    service.apply_batch(
        {"batch_id": "b1", "max_event_time_ms": 900,
         "metrics": [sample(0, value=2.0)]}
    )
    service.apply_batch(
        {"batch_id": "b2", "max_event_time_ms": 3900,
         "metrics": [sample(3000, value=8.0)]}
    )
    server = _HttpServer(service)
    yield server
    server.stop()


def test_http_query_gap_fill(http_service):
    status, body = http_service.post(
        "/v1/query", {"gap_fill": {"cpu.usage": 5000}}
    )
    assert status == 200
    assert [row["timestamp_ms"] for row in body["series"]] == [
        0, 1000, 2000, 3000
    ]

    status, body = http_service.post("/v1/query", {"gap_fill": {"cpu.usage": 0}})
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid gap_fill"}

    status, body = http_service.post("/v1/query", {"gap_fill": {"": 5}})
    assert status == 400
    assert body == {"code": "invalid_request", "message": "invalid gap_fill"}


def test_http_get_series_ignores_gap_fill(http_service):
    req = urlrequest.Request(http_service.url + "/v1/series")
    with urlrequest.urlopen(req) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    assert [row["timestamp_ms"] for row in body["series"]] == [0, 3000]
