"""Metric fusion: multi-source metric merging, downsampling and alert suppression."""

from __future__ import annotations

import hashlib
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


def alert_fingerprint(name: str, labels: dict) -> str:
    """Stable fingerprint of an alert series (metric name + full label set)."""
    canonical = json.dumps(
        {"name": name, "labels": labels},
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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


def _validate_rule(rule: Any, seen_rule_ids: set) -> dict:
    if not isinstance(rule, dict):
        raise ValueError("invalid suppression rule")
    rule_id = rule.get("rule_id")
    if not (isinstance(rule_id, str) and rule_id != ""):
        raise ValueError("invalid suppression rule")
    if rule_id in seen_rule_ids:
        raise ValueError("duplicate rule_id")
    seen_rule_ids.add(rule_id)

    metric = rule.get("metric")
    metric_prefix = rule.get("metric_prefix")
    if metric is not None and not (isinstance(metric, str) and metric != ""):
        raise ValueError("invalid selector")
    if metric_prefix is not None and not (
        isinstance(metric_prefix, str) and metric_prefix != ""
    ):
        raise ValueError("invalid selector")
    if metric is not None and metric_prefix is not None:
        raise ValueError("invalid selector")

    labels = rule.get("labels")
    if labels is None:
        labels = {}
    if not isinstance(labels, dict):
        raise ValueError("invalid selector")
    for key, value in labels.items():
        if not (isinstance(key, str) and isinstance(value, str)):
            raise ValueError("invalid selector")

    min_severity = rule.get("min_severity", "info")
    if min_severity not in SEVERITY_ORDER:
        raise ValueError("invalid severity")

    duration_ms = rule.get("duration_ms")
    if not _is_int(duration_ms) or duration_ms < 0:
        raise ValueError("invalid duration_ms")

    return {
        "rule_id": rule_id,
        "metric": metric,
        "metric_prefix": metric_prefix,
        "labels": labels,
        "min_severity": min_severity,
        "duration_ms": duration_ms,
    }


def _rule_matches(rule: dict, alert: dict) -> bool:
    metric = rule["metric"]
    if metric is not None and alert["name"] != metric:
        return False
    prefix = rule["metric_prefix"]
    if prefix is not None and not alert["name"].startswith(prefix):
        return False
    for key, value in rule["labels"].items():
        if alert["labels"].get(key) != value:
            return False
    return SEVERITY_ORDER[alert["severity"]] >= SEVERITY_ORDER[rule["min_severity"]]


def _rule_precedence(rule: dict) -> tuple:
    # More label conditions first, then a more precise metric selector
    # (exact > longer prefix > none), then the smallest rule_id.
    if rule["metric"] is not None:
        rank, prefix_len = 2, 0
    elif rule["metric_prefix"] is not None:
        rank, prefix_len = 1, len(rule["metric_prefix"])
    else:
        rank, prefix_len = 0, 0
    return (-len(rule["labels"]), -rank, -prefix_len, rule["rule_id"])


def _select_rule(rules: list, alert: dict) -> dict | None:
    matched = [rule for rule in rules if _rule_matches(rule, alert)]
    if not matched:
        return None
    return min(matched, key=_rule_precedence)


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


def _suppress_alerts_explained(alerts: list, rules: list) -> tuple[list, list, list]:
    # Organize the batch by metric name, canonical label set and trigger time
    # (alert_id breaks ties deterministically), then suppress per rule_id.
    ordered = sorted(
        alerts,
        key=lambda a: (
            a["name"],
            _canonical_labels(a["labels"]),
            a["timestamp_ms"],
            a["alert_id"],
        ),
    )

    suppressed_ids: set = set()
    explanations: list = []
    last_active: dict = {}  # rule_id -> (timestamp_ms, fingerprint) of the suppressor
    for alert in ordered:
        rule = _select_rule(rules, alert)
        if rule is None:
            continue  # no rule matches: the alert stays active
        fingerprint = alert_fingerprint(alert["name"], alert["labels"])
        duration_ms = rule["duration_ms"]
        suppressor = last_active.get(rule["rule_id"])
        if (
            suppressor is not None
            and suppressor[0] <= alert["timestamp_ms"] <= suppressor[0] + duration_ms
        ):
            suppressed_ids.add(alert["alert_id"])
            explanations.append(
                {
                    "suppressed_fingerprint": fingerprint,
                    "suppressor_fingerprint": suppressor[1],
                    "rule_id": rule["rule_id"],
                    "started_at": alert["timestamp_ms"],
                    "expires_at": suppressor[0] + duration_ms,
                }
            )
        else:
            last_active[rule["rule_id"]] = (alert["timestamp_ms"], fingerprint)

    result_alerts = [
        {
            "alert_id": alert["alert_id"],
            "severity": alert["severity"],
            "suppressed": alert["alert_id"] in suppressed_ids,
        }
        for alert in alerts
    ]
    suppressed_alert_ids = [a["alert_id"] for a in result_alerts if a["suppressed"]]
    return result_alerts, suppressed_alert_ids, explanations


class ExplanationStore:
    """Collects suppression explanation records across process() calls."""

    def __init__(self) -> None:
        self._records: list = []

    def add(self, record: dict) -> None:
        self._records.append(dict(record))

    def query(
        self,
        fingerprint: str | None = None,
        rule_id: str | None = None,
        suppressor_fingerprint: str | None = None,
        now_ms: Any = None,
    ) -> list:
        """Return stored explanations matching the given filters.

        Unknown fingerprints or rule ids yield an empty list. A record whose
        suppression period is over (``now_ms >= expires_at``) carries an
        explicit ``ended_at``; records still running omit it.
        """
        if fingerprint is not None and not isinstance(fingerprint, str):
            raise ValueError("invalid fingerprint")
        if suppressor_fingerprint is not None and not isinstance(
            suppressor_fingerprint, str
        ):
            raise ValueError("invalid fingerprint")
        if rule_id is not None and not isinstance(rule_id, str):
            raise ValueError("invalid rule_id")
        if now_ms is not None and not _valid_timestamp(now_ms):
            raise ValueError("invalid now_ms")

        results = []
        for record in self._records:
            if fingerprint is not None and record["suppressed_fingerprint"] != fingerprint:
                continue
            if (
                suppressor_fingerprint is not None
                and record["suppressor_fingerprint"] != suppressor_fingerprint
            ):
                continue
            if rule_id is not None and record["rule_id"] != rule_id:
                continue
            item = dict(record)
            if now_ms is not None and now_ms >= record["expires_at"]:
                item["ended_at"] = record["expires_at"]
            results.append(item)
        return results


def process(request: dict, explanation_store: ExplanationStore | None = None) -> dict:
    """Fuse metrics and alerts from a request mapping into a response mapping.

    With ``explain`` enabled the request may carry ``suppression_rules``; the
    response then also contains ``explanations`` and, when given, the records
    are appended to ``explanation_store``. Without ``explain`` the behavior is
    exactly the legacy one.
    """
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

    explain = request.get("explain", False)
    if not isinstance(explain, bool):
        raise ValueError("invalid explain")

    rules: list = []
    if explain:
        raw_rules = request.get("suppression_rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError("invalid suppression_rules")
        seen_rule_ids: set = set()
        rules = [_validate_rule(rule, seen_rule_ids) for rule in raw_rules]

    series = _downsample(metrics, downsample_ms)
    if explain:
        result_alerts, suppressed_alert_ids, explanations = _suppress_alerts_explained(
            alerts, rules
        )
    else:
        result_alerts, suppressed_alert_ids = _suppress_alerts(alerts, suppression_ms)

    result = {
        "series": series,
        "alerts": result_alerts,
        "suppressed_alert_ids": suppressed_alert_ids,
    }
    if explain:
        result["explanations"] = explanations
        if explanation_store is not None:
            for record in explanations:
                explanation_store.add(record)
    return result
