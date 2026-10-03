"""Metric fusion: multi-source metric merging, downsampling and alert suppression."""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from typing import Any

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}

_ALERT_FIELDS = ("source", "name", "labels", "alert_id", "rule", "timestamp_ms", "severity")


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


# ---------------------------------------------------------------------------
# Suppression explanations
# ---------------------------------------------------------------------------


def alert_fingerprint(name: str, labels: dict, timestamp_ms: Any) -> str:
    """Stable fingerprint of an alert event: metric name + full label set + time."""
    payload = "\n".join(
        ("v1", name, _canonical_labels(labels), str(timestamp_ms))
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_selector(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("invalid selector")
    metric = raw.get("metric")
    if not (isinstance(metric, str) and metric != ""):
        raise ValueError("invalid selector")
    labels = raw.get("labels", {})
    if labels is None:
        labels = {}
    if not isinstance(labels, dict):
        raise ValueError("invalid selector")
    for key, value in labels.items():
        if not (isinstance(key, str) and key != "" and isinstance(value, str)):
            raise ValueError("invalid selector")
    return {"metric": metric, "labels": dict(labels)}


def _metric_precision(metric_selector: str) -> int:
    # Higher = more specific: exact name > glob pattern > bare "*".
    if "*" not in metric_selector:
        return 2
    if metric_selector == "*":
        return 0
    return 1


def _metric_matches(metric_selector: str, name: str) -> bool:
    if "*" not in metric_selector:
        return metric_selector == name
    pattern = "^" + "".join(".*" if ch == "*" else re.escape(ch) for ch in metric_selector) + "$"
    return re.match(pattern, name) is not None


def _validate_suppression_rule(raw: Any, seen_rule_ids: set) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("invalid suppression rule")
    rule_id = raw.get("rule_id")
    if not (isinstance(rule_id, str) and rule_id != ""):
        raise ValueError("invalid rule_id")
    if rule_id in seen_rule_ids:
        raise ValueError("duplicate rule_id")
    selector = _validate_selector(raw.get("selector"))
    min_severity = raw.get("min_severity")
    if min_severity not in SEVERITY_ORDER:
        raise ValueError("invalid severity")
    duration = raw.get("suppression_ms")
    if not (_is_int(duration) and duration >= 0):
        raise ValueError("invalid suppression_ms")
    seen_rule_ids.add(rule_id)
    return {
        "rule_id": rule_id,
        "selector": selector,
        "min_severity": min_severity,
        "suppression_ms": duration,
    }


def _select_rule(alert: dict, rules: list) -> dict | None:
    """Pick the best rule matching an alert.

    Priority: more matched label conditions, then more specific metric selector,
    then the lexicographically smallest rule_id.
    """
    best = None
    best_key = None
    for rule in rules:
        selector = rule["selector"]
        if not _metric_matches(selector["metric"], alert["name"]):
            continue
        label_matchers = selector["labels"]
        alert_labels = alert["labels"]
        if any(alert_labels.get(key) != value for key, value in label_matchers.items()):
            continue
        if SEVERITY_ORDER[alert["severity"]] < SEVERITY_ORDER[rule["min_severity"]]:
            continue
        rank_key = (len(label_matchers), _metric_precision(selector["metric"]))
        if best is None or rank_key > best_key or (rank_key == best_key and rule["rule_id"] < best["rule_id"]):
            best = rule
            best_key = rank_key
    return best


class ExplanationRegistry:
    """Stores suppression explanation records across processed batches."""

    def __init__(self) -> None:
        self._records: dict[tuple, dict] = {}

    def add_all(self, records: list) -> None:
        for record in records:
            identity = (
                record["suppressed_fingerprint"],
                record["suppressor_fingerprint"],
                record["rule_id"],
                record["started_at"],
                record["expires_at"],
            )
            self._records[identity] = dict(record)

    def query(
        self,
        fingerprint: str | None = None,
        rule_id: str | None = None,
        now_ms: Any = None,
    ) -> list:
        if now_ms is None:
            current_ms = time.time() * 1000.0
        else:
            if not (_is_number(now_ms) and math.isfinite(now_ms) and now_ms >= 0):
                raise ValueError("invalid now_ms")
            current_ms = now_ms

        result = []
        for record in self._records.values():
            if fingerprint is not None and record["suppressed_fingerprint"] != fingerprint:
                continue
            if rule_id is not None and record["rule_id"] != rule_id:
                continue
            view = dict(record)
            # End time is reported only once known; it is never guessed up front.
            if current_ms >= record["expires_at"]:
                view["ended_at"] = record["expires_at"]
            result.append(view)
        result.sort(
            key=lambda r: (
                r["started_at"],
                r["rule_id"],
                r["suppressed_fingerprint"],
                r["suppressor_fingerprint"],
            )
        )
        return result

    def clear(self) -> None:
        self._records.clear()


_default_registry = ExplanationRegistry()


def query_explanations(
    fingerprint: str | None = None,
    rule_id: str | None = None,
    now_ms: Any = None,
    registry: ExplanationRegistry | None = None,
) -> list:
    """Return explanation records matching an alert fingerprint and/or rule_id.

    Ongoing records omit ended_at; records whose suppression duration has ended
    include ended_at. An unknown fingerprint or rule_id yields an empty list.
    """
    target = _default_registry if registry is None else registry
    return target.query(fingerprint=fingerprint, rule_id=rule_id, now_ms=now_ms)


def reset_explanations() -> None:
    """Clear the process-wide explanation registry (mainly for tests)."""
    _default_registry.clear()


def _process_with_explanations(
    alerts: list,
    series: list,
    rules: list,
    registry: ExplanationRegistry,
) -> dict:
    labels_keys = [_canonical_labels(alert["labels"]) for alert in alerts]
    fingerprints = [
        alert_fingerprint(alert["name"], alert["labels"], alert["timestamp_ms"])
        for alert in alerts
    ]

    # Chronological adjudication per metric (name + full label set), mirroring
    # the baseline ordering (timestamp_ms, then alert_id). Each chain holds the
    # previously valid (active) alerts that can still act as suppressors.
    order = sorted(
        range(len(alerts)),
        key=lambda i: (alerts[i]["timestamp_ms"], alerts[i]["alert_id"]),
    )
    chains: dict = {}
    suppression_by_index: dict = {}

    for index in order:
        alert = alerts[index]
        timestamp_ms = alert["timestamp_ms"]
        severity = SEVERITY_ORDER[alert["severity"]]
        rule = _select_rule(alert, rules)
        suppressor = None
        if rule is not None:
            duration = rule["suppression_ms"]
            chain = chains.get((alert["name"], labels_keys[index]), ())
            for anchor_ts, anchor_alert_id, anchor_severity, anchor_index in reversed(chain):
                if anchor_ts > timestamp_ms or (
                    anchor_ts == timestamp_ms and anchor_alert_id >= alert["alert_id"]
                ):
                    continue
                if timestamp_ms - anchor_ts > duration:
                    break  # every remaining anchor is even older
                if timestamp_ms == anchor_ts and severity > anchor_severity:
                    # Same-fingerprint duplicates keep the existing adjudication
                    # semantics: a higher severity breaks through at a tie.
                    break
                suppressor = (anchor_ts, anchor_index, rule)
                break

        if suppressor is None:
            chains.setdefault((alert["name"], labels_keys[index]), []).append(
                (timestamp_ms, alert["alert_id"], severity, index)
            )
        else:
            suppression_by_index[index] = suppressor

    output_alerts = []
    explanations = []
    suppressed_alert_ids: list = []

    # Output keeps the original alert fields and input order.
    for index, alert in enumerate(alerts):
        output_alert = {field: alert[field] for field in _ALERT_FIELDS}
        output_alert["fingerprint"] = fingerprints[index]
        suppression = suppression_by_index.get(index)
        if suppression is None:
            output_alert["status"] = "active"
        else:
            started_at, suppressor_index, rule = suppression
            output_alert["status"] = "suppressed"
            suppressed_alert_ids.append(alert["alert_id"])
            explanations.append(
                {
                    "suppressed_fingerprint": fingerprints[index],
                    "suppressor_fingerprint": fingerprints[suppressor_index],
                    "rule_id": rule["rule_id"],
                    "started_at": started_at,
                    "expires_at": started_at + rule["suppression_ms"],
                }
            )
        output_alerts.append(output_alert)

    # Commit explanations only after the whole batch has been produced.
    registry.add_all(explanations)

    return {
        "series": series,
        "alerts": output_alerts,
        "suppressed_alert_ids": suppressed_alert_ids,
        "explanations": explanations,
    }


def process(request: dict, *, registry: ExplanationRegistry | None = None) -> dict:
    """Fuse metrics and alerts from a request mapping into a response mapping."""
    if not isinstance(request, dict):
        raise ValueError("invalid request")

    downsample_ms = request.get("downsample_ms")
    if not _is_int(downsample_ms) or downsample_ms <= 0:
        raise ValueError("invalid downsample_ms")
    suppression_ms = request.get("suppression_ms")
    if not _is_int(suppression_ms) or suppression_ms < 0:
        raise ValueError("invalid suppression_ms")

    # The explanation subsystem is fully dormant unless explicitly enabled,
    # so legacy inputs, outputs and error behavior stay untouched.
    enabled_raw = request.get("enable_explanations", False)
    if not isinstance(enabled_raw, bool):
        raise ValueError("invalid enable_explanations")
    enabled = enabled_raw
    rules: list = []
    if enabled:
        raw_rules = request.get("suppression_rules", [])
        if raw_rules is None:
            raw_rules = []
        if not isinstance(raw_rules, list):
            raise ValueError("invalid suppression rules")
        seen_rule_ids: set = set()
        rules = [_validate_suppression_rule(raw, seen_rule_ids) for raw in raw_rules]

    raw_metrics = request.get("metrics")
    raw_alerts = request.get("alerts")
    if not isinstance(raw_metrics, list) or not isinstance(raw_alerts, list):
        raise ValueError("invalid request")

    metrics = [_validate_metric(metric) for metric in raw_metrics]
    seen_ids: set = set()
    alerts = [_validate_alert(alert, seen_ids) for alert in raw_alerts]

    series = _downsample(metrics, downsample_ms)
    result_alerts, suppressed_alert_ids = _suppress_alerts(alerts, suppression_ms)

    if not enabled:
        return {
            "series": series,
            "alerts": result_alerts,
            "suppressed_alert_ids": suppressed_alert_ids,
        }

    target_registry = _default_registry if registry is None else registry
    return _process_with_explanations(alerts, series, rules, target_registry)
