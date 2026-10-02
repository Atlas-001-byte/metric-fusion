"""Metric fusion: multi-source metric merging, downsampling and alert suppression."""

from __future__ import annotations

import json
import math
from typing import Any

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _canonical_labels(labels: dict) -> str:
    return json.dumps(labels, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _valid_timestamp(value: Any) -> bool:
    return _is_number(value) and math.isfinite(value) and value >= 0


def _validate_metric(metric: Any) -> dict:
    if not isinstance(metric, dict):
        raise ValueError("invalid metric")
    source = metric.get("source")
    name = metric.get("name")
    labels = metric.get("labels")
    timestamp_ms = metric.get("timestamp_ms")
    if not (
        isinstance(source, str)
        and source != ""
        and isinstance(name, str)
        and name != ""
        and isinstance(labels, dict)
        and _valid_timestamp(timestamp_ms)
    ):
        raise ValueError("invalid metric")
    value = metric.get("value")
    if not (_is_number(value) and math.isfinite(value)):
        raise ValueError("invalid value")
    return {
        "source": source,
        "name": name,
        "labels": labels,
        "timestamp_ms": timestamp_ms,
        "value": value,
    }


def _validate_alert(alert: Any, seen_ids: set) -> dict:
    if not isinstance(alert, dict):
        raise ValueError("invalid alert")
    source = alert.get("source")
    name = alert.get("name")
    labels = alert.get("labels")
    alert_id = alert.get("alert_id")
    rule = alert.get("rule")
    timestamp_ms = alert.get("timestamp_ms")
    if not (
        isinstance(source, str)
        and source != ""
        and isinstance(name, str)
        and name != ""
        and isinstance(labels, dict)
        and isinstance(alert_id, str)
        and alert_id != ""
        and isinstance(rule, str)
        and rule != ""
        and _valid_timestamp(timestamp_ms)
    ):
        raise ValueError("invalid alert")
    severity = alert.get("severity")
    if severity not in SEVERITY_ORDER:
        raise ValueError("invalid severity")
    if alert_id in seen_ids:
        raise ValueError("duplicate alert_id")
    seen_ids.add(alert_id)
    return {
        "source": source,
        "name": name,
        "labels": labels,
        "alert_id": alert_id,
        "rule": rule,
        "timestamp_ms": timestamp_ms,
        "severity": severity,
    }


def _downsample(metrics: list, downsample_ms: int) -> list:
    # Deduplicate identical points (same source/name/labels/timestamp):
    # the later occurrence wins.
    points: dict = {}
    for metric in metrics:
        labels_key = _canonical_labels(metric["labels"])
        point_key = (
            metric["source"],
            metric["name"],
            labels_key,
            metric["timestamp_ms"],
        )
        points[point_key] = metric["value"]

    buckets: dict = {}
    for (source, name, labels_key, timestamp_ms), value in points.items():
        start = (timestamp_ms // downsample_ms) * downsample_ms
        bucket_key = (name, labels_key, start)
        bucket = buckets.get(bucket_key)
        if bucket is None:
            bucket = {"sum": 0.0, "count": 0, "sources": set()}
            buckets[bucket_key] = bucket
        bucket["sum"] += value
        bucket["count"] += 1
        bucket["sources"].add(source)

    series = []
    for name, labels_key, start in sorted(buckets, key=lambda k: (k[0], k[1], k[2])):
        bucket = buckets[(name, labels_key, start)]
        count = bucket["count"]
        mean = bucket["sum"] / count + 0.0  # normalize -0.0
        series.append(
            {
                "name": name,
                "labels": json.loads(labels_key),
                "timestamp_ms": start,
                "value": round(mean, 6),
                "count": count,
                "sources": sorted(bucket["sources"]),
            }
        )
    return series


def _suppress_alerts(alerts: list, suppression_ms: int) -> tuple[list, list]:
    groups: dict = {}
    for alert in alerts:
        key = (alert["rule"], alert["name"], _canonical_labels(alert["labels"]))
        groups.setdefault(key, []).append(alert)

    suppressed_ids: set = set()
    for group in groups.values():
        group.sort(key=lambda a: (a["timestamp_ms"], a["alert_id"]))
        last_ts = None
        last_severity = -1
        for alert in group:
            severity = SEVERITY_ORDER[alert["severity"]]
            if last_ts is None:
                emit = True
            elif alert["timestamp_ms"] - last_ts <= suppression_ms:
                # Within the suppression window: only a higher severity breaks through.
                emit = severity > last_severity
            else:
                emit = True
            if emit:
                last_ts = alert["timestamp_ms"]
                last_severity = severity
            else:
                suppressed_ids.add(alert["alert_id"])

    result_alerts = [
        {
            "alert_id": alert["alert_id"],
            "severity": alert["severity"],
            "suppressed": alert["alert_id"] in suppressed_ids,
        }
        for alert in alerts
    ]
    return result_alerts, [a["alert_id"] for a in result_alerts if a["suppressed"]]


def process(request: dict) -> dict:
    """Fuse metrics and alerts from a request mapping into a response mapping."""
    if not isinstance(request, dict):
        raise ValueError("invalid request")

    downsample_ms = request.get("downsample_ms")
    if not _is_int(downsample_ms) or downsample_ms <= 0:
        raise ValueError("invalid downsample_ms")
    suppression_ms = request.get("suppression_ms")
    if not _is_int(suppression_ms) or suppression_ms < 0:
        raise ValueError("invalid suppression_ms")

    raw_metrics = request.get("metrics")
    raw_alerts = request.get("alerts")
    if not isinstance(raw_metrics, list) or not isinstance(raw_alerts, list):
        raise ValueError("invalid request")

    metrics = [_validate_metric(metric) for metric in raw_metrics]
    seen_ids: set = set()
    alerts = [_validate_alert(alert, seen_ids) for alert in raw_alerts]

    series = _downsample(metrics, downsample_ms)
    result_alerts, suppressed_alert_ids = _suppress_alerts(alerts, suppression_ms)

    return {
        "series": series,
        "alerts": result_alerts,
        "suppressed_alert_ids": suppressed_alert_ids,
    }
