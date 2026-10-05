"""Metric fusion: multi-source metric merging, downsampling and alert suppression."""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from typing import Any

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}

AGGREGATION_FUNCTIONS = ("avg", "min", "max", "sum", "last", "median", "p95", "p99")

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


def _validate_aggregations(raw: Any) -> dict:
    """Validate an ``aggregations`` mapping of exact metric name to function.

    Returns ``{}`` for an absent/None mapping (every metric uses ``avg``).
    Anything that is not a mapping of non-empty string keys to one of the
    supported function names raises ``ValueError("invalid aggregation")``.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("invalid aggregation")
    validated: dict = {}
    for key, value in raw.items():
        if not (isinstance(key, str) and key != ""):
            raise ValueError("invalid aggregation")
        if not (isinstance(value, str) and value in AGGREGATION_FUNCTIONS):
            raise ValueError("invalid aggregation")
        validated[key] = value
    return validated


def _validate_source_quorum(raw: Any) -> dict:
    """Validate a ``source_quorum`` mapping of exact metric name to threshold.

    Returns ``{}`` for an absent/None mapping (every window is output).
    Values must be positive integers — booleans, zero, negatives and floats
    are rejected. Anything invalid raises
    ``ValueError("invalid source_quorum")``.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("invalid source_quorum")
    validated: dict = {}
    for key, value in raw.items():
        if not (isinstance(key, str) and key != ""):
            raise ValueError("invalid source_quorum")
        if not (_is_int(value) and value > 0):
            raise ValueError("invalid source_quorum")
        validated[key] = value
    return validated


def _validate_source_weights(raw: Any) -> dict:
    """Validate a ``source_weights`` mapping of exact metric name to per-source weights.

    Returns ``{}`` for an absent/None mapping (every metric merges with equal
    weights, i.e. the existing plain aggregation). Each target maps to either
    a ``{source: weight}`` mapping or a list of ``{"source", "weight"}``
    entries; weights must be finite numbers >= 0, a target must list at least
    one source, and no source may be configured twice for the same target.
    Anything invalid raises ``ValueError("invalid source_weights")``.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("invalid source_weights")
    validated: dict = {}
    for key, value in raw.items():
        if not (isinstance(key, str) and key != ""):
            raise ValueError("invalid source_weights")
        validated[key] = _validate_weight_entries(value)
    return validated


def _validate_weight_entries(raw: Any) -> dict:
    if isinstance(raw, dict):
        entries = [{"source": source, "weight": weight} for source, weight in raw.items()]
    elif isinstance(raw, list):
        entries = raw
    else:
        raise ValueError("invalid source_weights")
    if not entries:
        # A target configured with an empty source set is invalid.
        raise ValueError("invalid source_weights")
    weights: dict = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid source_weights")
        source = entry.get("source")
        if not (isinstance(source, str) and source != ""):
            raise ValueError("invalid source_weights")
        if source in weights:
            raise ValueError("invalid source_weights")
        weight = entry.get("weight")
        if not (_is_number(weight) and math.isfinite(weight) and weight >= 0):
            raise ValueError("invalid source_weights")
        weights[source] = weight
    return weights


def _validate_source_priority(raw: Any) -> dict:
    """Validate a ``source_priority`` mapping of exact metric name to an ordered
    list of source names.

    Returns ``{}`` for an absent/None mapping. Each target must map to a
    non-empty list of non-empty source strings with no source repeated. Anything
    invalid raises ``ValueError("invalid source_priority")``.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict) or not raw:
        raise ValueError("invalid source_priority")
    validated: dict = {}
    for key, sources in raw.items():
        if not (isinstance(key, str) and key != ""):
            raise ValueError("invalid source_priority")
        if not isinstance(sources, list) or not sources:
            raise ValueError("invalid source_priority")
        ordered: list = []
        for source in sources:
            if not (isinstance(source, str) and source != ""):
                raise ValueError("invalid source_priority")
            if source in ordered:
                raise ValueError("invalid source_priority")
            ordered.append(source)
        validated[key] = ordered
    return validated


def _new_bucket() -> dict:
    return {
        "sum": 0.0,
        "count": 0,
        "sources": set(),
        "min": None,
        "max": None,
        "last": None,
        # Every deduplicated window sample value; distribution aggregations
        # (median/p95/p99) sort this on demand, so arrival order never matters.
        "samples": [],
        # source -> [sum, count, min, max, last, samples]; every extra
        # statistic beyond sum/count is needed only by priority failover and
        # distribution aggregation.
        "per_source": {},
    }


def _bucket_add(bucket: dict, source: str, timestamp_ms: Any, value: Any) -> None:
    bucket["sum"] += value
    bucket["count"] += 1
    bucket["sources"].add(source)
    bucket["samples"].append(value)
    per_source = bucket["per_source"].get(source)
    if per_source is None:
        per_source = bucket["per_source"][source] = [0.0, 0, None, None, None, []]
    per_source[0] += value
    per_source[1] += 1
    per_source[5].append(value)
    source_min = per_source[2]
    if source_min is None or value < source_min:
        per_source[2] = value
    source_max = per_source[3]
    if source_max is None or value > source_max:
        per_source[3] = value
    source_last = per_source[4]
    if source_last is None or timestamp_ms > source_last[0]:
        per_source[4] = (timestamp_ms, value)
    if bucket["min"] is None or value < bucket["min"]:
        bucket["min"] = value
    if bucket["max"] is None or value > bucket["max"]:
        bucket["max"] = value
    last = bucket["last"]
    # "last" is the sample with the greatest timestamp; ties resolve to the
    # lexicographically greatest source.
    if last is None or (timestamp_ms, source) > (last[0], last[1]):
        bucket["last"] = (timestamp_ms, source, value)


def _distribution_value(samples: list, func: str) -> float:
    """Median / percentile over deduplicated window samples.

    ``median`` is the middle value, or the arithmetic mean of the two middle
    values for an even sample count. ``p95``/``p99`` use the one-based nearest
    rank ``ceil(q * n)`` with no interpolation. Values are sorted on demand,
    so the result is independent of sample arrival order.
    """
    ordered = sorted(samples)
    n = len(ordered)
    if func == "median":
        middle = n // 2
        if n % 2 == 1:
            value = ordered[middle]
        else:
            value = (ordered[middle - 1] + ordered[middle]) / 2
    elif func == "p95":
        rank = math.ceil(0.95 * n)
        value = ordered[rank - 1]
    else:  # p99
        rank = math.ceil(0.99 * n)
        value = ordered[rank - 1]
    return round(value + 0.0, 6)  # normalize -0.0


def _bucket_value(bucket: dict, func: str) -> float:
    if func == "min":
        value = bucket["min"]
    elif func == "max":
        value = bucket["max"]
    elif func == "sum":
        value = bucket["sum"]
    elif func == "last":
        value = bucket["last"][2]
    elif func in ("median", "p95", "p99"):
        value = _distribution_value(bucket["samples"], func)
    else:  # avg
        value = bucket["sum"] / bucket["count"]
    return round(value + 0.0, 6)  # normalize -0.0


def _weighted_bucket_value(bucket: dict, weights: dict):
    """Weighted merge of a window's deduplicated samples, or None.

    Only configured sources participate. A source with a positive weight
    contributes each of its samples as ``value * weight`` to the numerator and
    ``weight`` to the denominator; a zero-weight source counts towards
    availability only and never changes the value. When no sample carries an
    effective (positive) weight the window has no numeric result.
    """
    numerator = 0.0
    denominator = 0.0
    for source, stats in bucket["per_source"].items():
        weight = weights.get(source)
        if weight is None or weight <= 0:
            continue
        numerator += stats[0] * weight
        denominator += stats[1] * weight
    if denominator == 0:
        return None
    return round(numerator / denominator + 0.0, 6)  # normalize -0.0


def _weighted_row(name: str, labels_key: str, start: Any, bucket: dict, weights: dict) -> dict:
    # Sources not listed in the target's weight configuration do not
    # participate at all: they contribute neither value nor availability.
    participating = [source for source in bucket["sources"] if source in weights]
    value = _weighted_bucket_value(bucket, weights)
    row = {
        "name": name,
        "labels": json.loads(labels_key),
        "timestamp_ms": start,
        "value": value,
        "count": sum(bucket["per_source"][source][1] for source in participating),
        "sources": sorted(participating),
    }
    if value is None:
        # The window had samples but no effective weight: mark it instead of
        # emitting a number. Windows without any sample keep the existing
        # no-data semantics (no row at all).
        row["weight_missing"] = True
    return row


def _source_stats_value(stats: list, func: str) -> float:
    """Aggregate one winning source's window samples with ``func``."""
    source_sum, source_count, source_min, source_max, source_last, source_samples = stats
    if func == "min":
        value = source_min
    elif func == "max":
        value = source_max
    elif func == "sum":
        value = source_sum
    elif func == "last":
        value = source_last[1]
    elif func in ("median", "p95", "p99"):
        value = _distribution_value(source_samples, func)
    else:  # avg
        value = source_sum / source_count
    return round(value + 0.0, 6)  # normalize -0.0


def _priority_row(
    name: str, labels_key: str, start: Any, bucket: dict, priorities: list, func: str
) -> dict:
    """Failover row for a priority-configured target.

    The quorum check has already passed against the full deduplicated source
    set. The first configured source that actually has a winning sample in the
    window provides every sample of the row; sources not configured for the
    target never participate. If none of the configured sources appears, the
    row is emitted with a null value and ``priority_missing``.
    """
    winner = next((source for source in priorities if source in bucket["per_source"]), None)
    if winner is None:
        return {
            "name": name,
            "labels": json.loads(labels_key),
            "timestamp_ms": start,
            "value": None,
            "count": 0,
            "sources": [],
            "priority_missing": True,
        }
    stats = bucket["per_source"][winner]
    return {
        "name": name,
        "labels": json.loads(labels_key),
        "timestamp_ms": start,
        "value": _source_stats_value(stats, func),
        "count": stats[1],
        "sources": [winner],
    }


def _downsample(
    metrics: list,
    downsample_ms: int,
    aggregations: dict | None = None,
    source_quorum: dict | None = None,
    source_weights: dict | None = None,
    source_priority: dict | None = None,
) -> list:
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
            bucket = _new_bucket()
            buckets[bucket_key] = bucket
        _bucket_add(bucket, source, timestamp_ms, value)

    series = []
    for name, labels_key, start in sorted(buckets, key=lambda k: (k[0], k[1], k[2])):
        bucket = buckets[(name, labels_key, start)]
        # The quorum threshold is judged against the full deduplicated source
        # set of the window — never the sample or request count. Windows below
        # the threshold are dropped entirely: no fill points or partial rows.
        if source_quorum and name in source_quorum and len(bucket["sources"]) < source_quorum[name]:
            continue
        weights = source_weights.get(name) if source_weights else None
        if weights is not None:
            # Weight-enabled targets merge by configured source weights; the
            # aggregation-function selection does not apply to them.
            series.append(_weighted_row(name, labels_key, start, bucket, weights))
            continue
        priorities = source_priority.get(name) if source_priority else None
        if priorities is not None:
            func = aggregations.get(name, "avg") if aggregations else "avg"
            series.append(_priority_row(name, labels_key, start, bucket, priorities, func))
            continue
        func = aggregations.get(name, "avg") if aggregations else "avg"
        series.append(
            {
                "name": name,
                "labels": json.loads(labels_key),
                "timestamp_ms": start,
                "value": _bucket_value(bucket, func),
                "count": bucket["count"],
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


# ---------------------------------------------------------------------------
# Time-window suppression rules (per source and label dimensions)
# ---------------------------------------------------------------------------

WINDOW_STATUS_MISSED = "missed"  # 未命中
WINDOW_STATUS_PENDING = "pending"  # 观察中
WINDOW_STATUS_SUPPRESSED = "suppressed"  # 抑制中
WINDOW_STATUS_RECOVERED = "recovered"  # 已恢复

WINDOW_STATUSES = (
    WINDOW_STATUS_MISSED,
    WINDOW_STATUS_PENDING,
    WINDOW_STATUS_SUPPRESSED,
    WINDOW_STATUS_RECOVERED,
)


class RuleConfigurationError(ValueError):
    """A time-window suppression rule (or an event handed to the rule engine
    without a timestamp) is invalid."""


class EventTimestampError(ValueError):
    """An event timestamp cannot be ordered on the event-time axis."""


def _validate_window_rule(raw: Any, seen_rule_ids: set) -> dict:
    if not isinstance(raw, dict):
        raise RuleConfigurationError("invalid window suppression rule")
    rule_id = raw.get("rule_id")
    if not (isinstance(rule_id, str) and rule_id != ""):
        raise RuleConfigurationError("invalid rule_id")
    if rule_id in seen_rule_ids:
        raise RuleConfigurationError("duplicate rule_id")
    source = raw.get("source")
    if not (isinstance(source, str) and source != ""):
        raise RuleConfigurationError("invalid source")
    metric = raw.get("metric")
    if not (isinstance(metric, str) and metric != ""):
        raise RuleConfigurationError("invalid metric")
    labels = raw.get("labels", {})
    if labels is None:
        labels = {}
    if not isinstance(labels, dict):
        raise RuleConfigurationError("invalid labels")
    for key, value in labels.items():
        if not (isinstance(key, str) and key != "" and isinstance(value, str)):
            raise RuleConfigurationError("invalid labels")
    pending_ms = raw.get("pending_ms")
    if not (_is_int(pending_ms) and pending_ms >= 0):
        raise RuleConfigurationError("invalid pending_ms")
    suppression_ms = raw.get("suppression_ms")
    if not (_is_int(suppression_ms) and suppression_ms >= 0):
        raise RuleConfigurationError("invalid suppression_ms")
    recovery_ms = raw.get("recovery_ms")
    if not (_is_int(recovery_ms) and recovery_ms >= 0):
        raise RuleConfigurationError("invalid recovery_ms")
    seen_rule_ids.add(rule_id)
    return {
        "rule_id": rule_id,
        "source": source,
        "metric": metric,
        "labels": dict(labels),
        "pending_ms": pending_ms,
        "suppression_ms": suppression_ms,
        "recovery_ms": recovery_ms,
    }


def _validate_window_rules(raw: Any) -> list:
    """Validate a list of time-window suppression rules (all or nothing)."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise RuleConfigurationError("invalid window suppression rules")
    seen_rule_ids: set = set()
    return [_validate_window_rule(rule, seen_rule_ids) for rule in raw]


class _WindowComboState:
    """Suppression episode of one (rule_id, source, labels) combination."""

    __slots__ = (
        "labels",
        "active_start",
        "run_start",
        "suppression_start",
        "suppression_end",
        "recovery_deadline",
    )

    def __init__(self, labels: dict) -> None:
        self.labels = dict(labels)
        self.active_start = None
        self.run_start = None
        self.suppression_start = None
        self.suppression_end = None
        self.recovery_deadline = None


class WindowSuppressionEngine:
    """Event-time state machine for time-window suppression rules.

    One episode is tracked per ``(rule_id, source, canonical labels)``; label
    combinations never influence each other. Matching events accumulate over
    ``pending_ms`` before the episode turns ``suppressed``; the suppression
    window never extends on repeated matches. Once ``suppression_ms`` has
    elapsed the episode is in recovery observation: a match restarts the
    observation (the recorded suppression end stays untouched), and only a
    full quiet ``recovery_ms`` returns the combination to ``missed``.
    """

    def __init__(self, rules: list | None = None) -> None:
        self._rules: list = []
        self._states: dict = {}
        self._last_event_time = None
        if rules is not None:
            self.set_rules(rules)

    @property
    def rules(self) -> list:
        return [dict(rule, labels=dict(rule["labels"])) for rule in self._rules]

    def set_rules(self, rules: list | None) -> None:
        """Replace the rule set; takes effect for the next incoming event.

        Already recorded episodes are kept untouched: changed durations never
        retroactively alter recorded hits, and states of removed rules stay
        queryable by rule_id — removal only stops future matching.
        """
        validated = _validate_window_rules(rules)
        self._rules = validated

    def reset(self) -> None:
        """Drop all recorded episodes; the configured rules are kept."""
        self._states = {}
        self._last_event_time = None

    # -- event intake ---------------------------------------------------------

    def record_event(self, event: dict) -> None:
        """Feed one observation (metric sample or alert) into the engine."""
        if not isinstance(event, dict) or event.get("timestamp_ms") is None:
            raise RuleConfigurationError("missing event timestamp")
        timestamp_ms = event["timestamp_ms"]
        if not _valid_timestamp(timestamp_ms):
            raise EventTimestampError("unsortable event timestamp")
        if self._last_event_time is None or timestamp_ms > self._last_event_time:
            self._last_event_time = timestamp_ms
        source = event.get("source")
        name = event.get("name")
        labels = event.get("labels")
        if not (
            isinstance(source, str)
            and source != ""
            and isinstance(name, str)
            and isinstance(labels, dict)
        ):
            return
        labels_key = _canonical_labels(labels)
        for rule in self._matching_rules(source, name, labels):
            key = (rule["rule_id"], source, labels_key)
            state = self._states.get(key)
            if state is None:
                state = _WindowComboState(labels)
                self._states[key] = state
            self._advance(state, timestamp_ms, rule)

    def _matching_rules(self, source: str, name: str, labels: dict):
        for rule in self._rules:
            if rule["source"] != source:
                continue
            if not _metric_matches(rule["metric"], name):
                continue
            if any(labels.get(key) != value for key, value in rule["labels"].items()):
                continue
            yield rule

    def _advance(self, state: _WindowComboState, timestamp_ms: Any, rule: dict) -> None:
        if state.suppression_end is not None:
            if timestamp_ms <= state.suppression_end:
                # Inside the suppression window: repeated matches never
                # extend it.
                return
            if timestamp_ms <= state.recovery_deadline:
                # A match during recovery restarts the observation; the
                # recorded suppression end stays unchanged.
                state.recovery_deadline = timestamp_ms + rule["recovery_ms"]
                return
            # Recovery completed quietly: the episode is over and this event
            # starts a fresh observation run.
            state.suppression_start = None
            state.suppression_end = None
            state.recovery_deadline = None
            state.run_start = None
        if state.run_start is None:
            state.run_start = timestamp_ms
            state.active_start = timestamp_ms
        if timestamp_ms - state.run_start >= rule["pending_ms"]:
            state.suppression_start = timestamp_ms
            state.suppression_end = timestamp_ms + rule["suppression_ms"]
            state.recovery_deadline = state.suppression_end + rule["recovery_ms"]

    # -- suppression decisions --------------------------------------------------

    def is_suppressed(self, source: str, name: str, labels: dict, timestamp_ms: Any) -> bool:
        """Whether an alert emitted at ``timestamp_ms`` is suppressed.

        When several rules hit the same event, the aggregate follows the
        suppression window with the earliest end.
        """
        if not (
            isinstance(source, str)
            and isinstance(name, str)
            and isinstance(labels, dict)
            and _valid_timestamp(timestamp_ms)
        ):
            return False
        labels_key = _canonical_labels(labels)
        earliest_end = None
        for rule in self._matching_rules(source, name, labels):
            state = self._states.get((rule["rule_id"], source, labels_key))
            if state is None or state.suppression_end is None:
                continue
            if not (state.suppression_start <= timestamp_ms <= state.recovery_deadline):
                continue
            if earliest_end is None or state.suppression_end < earliest_end:
                earliest_end = state.suppression_end
        return earliest_end is not None and timestamp_ms <= earliest_end

    # -- queries ----------------------------------------------------------------

    def query(
        self,
        rule_id: str | None = None,
        source: str | None = None,
        labels: dict | None = None,
        now_ms: Any = None,
    ) -> list:
        """Return recorded suppression states, sorted by rule_id/source/labels.

        ``now_ms`` defaults to the latest event time seen by the engine, so
        adjudication stays on the event-time axis.
        """
        if now_ms is None:
            now = self._last_event_time if self._last_event_time is not None else 0
        elif _valid_timestamp(now_ms):
            now = now_ms
        else:
            raise EventTimestampError("unsortable event timestamp")
        records = []
        for (state_rule_id, state_source, _labels_key), state in self._states.items():
            if rule_id is not None and state_rule_id != rule_id:
                continue
            if source is not None and state_source != source:
                continue
            if labels is not None and any(
                state.labels.get(key) != value for key, value in labels.items()
            ):
                continue
            records.append(
                {
                    "rule_id": state_rule_id,
                    "source": state_source,
                    "labels": dict(state.labels),
                    "active_start_ms": state.active_start,
                    "suppression_end_ms": state.suppression_end,
                    "status": self._status_of(state, now),
                }
            )
        records.sort(
            key=lambda record: (
                record["rule_id"],
                record["source"],
                _canonical_labels(record["labels"]),
            )
        )
        return records

    @staticmethod
    def _status_of(state: _WindowComboState, now: Any) -> str:
        if state.suppression_end is not None:
            if now <= state.suppression_end:
                return WINDOW_STATUS_SUPPRESSED
            if now <= state.recovery_deadline:
                return WINDOW_STATUS_RECOVERED
            return WINDOW_STATUS_MISSED
        if state.run_start is not None:
            return WINDOW_STATUS_PENDING
        return WINDOW_STATUS_MISSED


_default_window_engine = WindowSuppressionEngine()


def query_window_suppressions(
    rule_id: str | None = None,
    source: str | None = None,
    labels: dict | None = None,
    now_ms: Any = None,
    engine: WindowSuppressionEngine | None = None,
) -> list:
    """Query recorded time-window suppression states (see ``WindowSuppressionEngine.query``)."""
    target = _default_window_engine if engine is None else engine
    return target.query(rule_id=rule_id, source=source, labels=labels, now_ms=now_ms)


def reset_window_suppressions() -> None:
    """Clear the process-wide window-suppression episodes (mainly for tests)."""
    _default_window_engine.reset()


def _feed_window_events(engine: WindowSuppressionEngine, metrics: list, alerts: list) -> set:
    """Drive the engine with one batch of events in event-time order.

    Returns the ids of alerts suppressed by a window rule. An alert is
    evaluated against the state right before its own event is recorded, so
    the observation that triggers a suppression is still emitted and only
    later observations are suppressed.
    """
    events = [(metric["timestamp_ms"], index, metric, None) for index, metric in enumerate(metrics)]
    events += [
        (alert["timestamp_ms"], len(metrics) + index, alert, alert["alert_id"])
        for index, alert in enumerate(alerts)
    ]
    events.sort(key=lambda event: (event[0], event[1]))
    suppressed_ids: set = set()
    for timestamp_ms, _index, event, alert_id in events:
        if alert_id is not None and engine.is_suppressed(
            event["source"], event["name"], event["labels"], timestamp_ms
        ):
            suppressed_ids.add(alert_id)
        engine.record_event(event)
    return suppressed_ids


# ---------------------------------------------------------------------------
# Maintenance windows (planned-maintenance alert suppression)
# ---------------------------------------------------------------------------


class MaintenanceWindowError(ValueError):
    """A maintenance-window configuration (or one of its fields) is invalid."""


def _validate_maintenance_window(raw: Any, seen_window_ids: set) -> dict:
    if not isinstance(raw, dict):
        raise MaintenanceWindowError("invalid maintenance_window")
    window_id = raw.get("window_id")
    if not (isinstance(window_id, str) and window_id != ""):
        raise MaintenanceWindowError("invalid maintenance_window")
    if window_id in seen_window_ids:
        raise MaintenanceWindowError("invalid maintenance_window")
    start_ms = raw.get("start_ms")
    end_ms = raw.get("end_ms")
    # The interval is half-open: [start_ms, end_ms).
    if not (_valid_timestamp(start_ms) and _valid_timestamp(end_ms) and end_ms > start_ms):
        raise MaintenanceWindowError("invalid maintenance_window")
    source = raw.get("source")
    if source is not None and not (isinstance(source, str) and source != ""):
        raise MaintenanceWindowError("invalid maintenance_window")
    name = raw.get("name")
    if name is not None and not (isinstance(name, str) and name != ""):
        raise MaintenanceWindowError("invalid maintenance_window")
    labels = raw.get("labels")
    if labels is not None:
        if not isinstance(labels, dict):
            raise MaintenanceWindowError("invalid maintenance_window")
        for key in labels:
            if not (isinstance(key, str) and key != ""):
                raise MaintenanceWindowError("invalid maintenance_window")
    if source is None and name is None and labels is None:
        # A window must carry at least one matching condition.
        raise MaintenanceWindowError("invalid maintenance_window")
    seen_window_ids.add(window_id)
    return {
        "window_id": window_id,
        "start_ms": start_ms,
        "end_ms": end_ms,
        "source": source,
        "name": name,
        "labels": dict(labels) if labels is not None else None,
    }


def _validate_maintenance_windows(raw: Any) -> list:
    """Validate a ``maintenance_windows`` list (all or nothing).

    Returns ``[]`` for an absent/None value (no maintenance suppression).
    Anything invalid raises ``ValueError("invalid maintenance_window")``.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise MaintenanceWindowError("invalid maintenance_window")
    seen_window_ids: set = set()
    return [_validate_maintenance_window(window, seen_window_ids) for window in raw]


def _maintenance_window_matches(window: dict, alert: dict) -> bool:
    # Only the alert's timestamp_ms is consulted for the time dimension.
    if not (window["start_ms"] <= alert["timestamp_ms"] < window["end_ms"]):
        return False
    if window["source"] is not None and alert["source"] != window["source"]:
        return False
    if window["name"] is not None and alert["name"] != window["name"]:
        return False
    labels = window["labels"]
    if labels is not None and any(
        alert["labels"].get(key) != value for key, value in labels.items()
    ):
        return False
    return True


def _maintenance_suppressed_ids(alerts: list, windows: list) -> set:
    """Ids of alerts falling inside at least one maintenance window."""
    if not windows:
        return set()
    return {
        alert["alert_id"]
        for alert in alerts
        if any(_maintenance_window_matches(window, alert) for window in windows)
    }


def process(
    request: dict,
    *,
    registry: ExplanationRegistry | None = None,
    window_engine: WindowSuppressionEngine | None = None,
) -> dict:
    """Fuse metrics and alerts from a request mapping into a response mapping."""
    if not isinstance(request, dict):
        raise ValueError("invalid request")

    downsample_ms = request.get("downsample_ms")
    if not _is_int(downsample_ms) or downsample_ms <= 0:
        raise ValueError("invalid downsample_ms")
    suppression_ms = request.get("suppression_ms")
    if not _is_int(suppression_ms) or suppression_ms < 0:
        raise ValueError("invalid suppression_ms")

    # Per-metric aggregation selection; validated before any state is touched
    # so a failure leaves nothing partially applied.
    aggregations = _validate_aggregations(request.get("aggregations"))

    # Optional per-metric source coverage thresholds; validated up front for
    # the same all-or-nothing reason as aggregations.
    source_quorum = _validate_source_quorum(request.get("source_quorum"))

    # Optional per-target source weights; validated up front (all or nothing)
    # so a rejected configuration leaves nothing partially applied. Targets
    # absent from the mapping keep the default equal-weight merge.
    source_weights = _validate_source_weights(request.get("source_weights"))

    # Optional per-target ordered source failover; validated up front like the
    # other per-metric query options. The same metric target cannot be tuned by
    # both weights and priority.
    source_priority = _validate_source_priority(request.get("source_priority"))
    if source_priority.keys() & source_weights.keys():
        raise ValueError("invalid source_priority")

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

    # Time-window suppression rules stay dormant unless the request carries
    # them; they are validated (all or nothing) up front and only become
    # effective once the whole request has passed validation.
    raw_window_rules = request.get("window_suppression_rules")
    validated_window_rules: list | None = None
    if raw_window_rules is not None:
        validated_window_rules = _validate_window_rules(raw_window_rules)

    # Maintenance windows stay dormant unless the request carries them; they
    # are validated (all or nothing) up front like every other optional config.
    maintenance_windows = _validate_maintenance_windows(request.get("maintenance_windows"))

    raw_metrics = request.get("metrics")
    raw_alerts = request.get("alerts")
    if not isinstance(raw_metrics, list) or not isinstance(raw_alerts, list):
        raise ValueError("invalid request")

    metrics = [_validate_metric(metric) for metric in raw_metrics]
    seen_ids: set = set()
    alerts = [_validate_alert(alert, seen_ids) for alert in raw_alerts]

    series = _downsample(
        metrics,
        downsample_ms,
        aggregations,
        source_quorum,
        source_weights,
        source_priority,
    )

    window_suppressed_ids: set = set()
    engine: WindowSuppressionEngine | None = None
    if validated_window_rules is not None:
        engine = _default_window_engine if window_engine is None else window_engine
        engine.set_rules(validated_window_rules)
        window_suppressed_ids = _feed_window_events(engine, metrics, alerts)

    maintenance_suppressed_ids = _maintenance_suppressed_ids(alerts, maintenance_windows)
    extra_suppressed_ids = window_suppressed_ids | maintenance_suppressed_ids

    result_alerts, suppressed_alert_ids = _suppress_alerts(alerts, suppression_ms)
    if extra_suppressed_ids:
        for entry in result_alerts:
            if entry["alert_id"] in extra_suppressed_ids:
                entry["suppressed"] = True
        suppressed_alert_ids = [entry["alert_id"] for entry in result_alerts if entry["suppressed"]]

    if not enabled:
        result = {
            "series": series,
            "alerts": result_alerts,
            "suppressed_alert_ids": suppressed_alert_ids,
        }
        if engine is not None:
            result["suppression_states"] = engine.query()
        return result

    target_registry = _default_registry if registry is None else registry
    result = _process_with_explanations(alerts, series, rules, target_registry)
    if extra_suppressed_ids:
        for output_alert in result["alerts"]:
            if output_alert["alert_id"] in extra_suppressed_ids:
                output_alert["status"] = "suppressed"
        merged_ids = set(result["suppressed_alert_ids"]) | extra_suppressed_ids
        result["suppressed_alert_ids"] = [
            output_alert["alert_id"]
            for output_alert in result["alerts"]
            if output_alert["alert_id"] in merged_ids
        ]
    if engine is not None:
        result["suppression_states"] = engine.query()
    return result


# ---------------------------------------------------------------------------
# Metric batch patches and late-data correction
# ---------------------------------------------------------------------------

BATCH_APPLIED = "applied"
BATCH_RETRACTED = "retracted"


class BatchError(ValueError):
    """Structured batch-API failure carrying an HTTP status and a stable code."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def _canonical_sample(metric: dict) -> str:
    return json.dumps(
        {
            "source": metric["source"],
            "name": metric["name"],
            "labels": metric["labels"],
            "timestamp_ms": metric["timestamp_ms"],
            "value": metric["value"],
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _canonical_alert(alert: dict) -> str:
    return json.dumps(
        {field: alert[field] for field in _ALERT_FIELDS},
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _batch_fingerprint(max_event_time_ms: Any, metrics: list, alerts: list) -> str:
    """Content fingerprint of a batch, independent of sample ordering."""
    payload = "\n".join(
        ["v1", repr(max_event_time_ms)]
        + sorted(_canonical_sample(metric) for metric in metrics)
        + ["--"]
        + sorted(_canonical_alert(alert) for alert in alerts)
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class MetricBatchService:
    """Stateful metric-stream store accepting idempotent, order-independent batches.

    Samples are kept per stream so that late batches recompute exactly the
    downsample windows they touch; queries always reflect the current state.
    Point conflicts across batches resolve deterministically by batch rank
    ``(max_event_time_ms, batch_id)`` — the higher rank wins — so the final
    aggregates do not depend on batch arrival order.
    """

    def __init__(
        self,
        downsample_ms: int | None = None,
        suppression_ms: int = 0,
        suppression_rules: list | None = None,
        enable_explanations: bool = False,
        registry: ExplanationRegistry | None = None,
        window_suppression_rules: list | None = None,
        maintenance_windows: list | None = None,
    ) -> None:
        if downsample_ms is not None and (not _is_int(downsample_ms) or downsample_ms <= 0):
            raise ValueError("invalid downsample_ms")
        if not _is_int(suppression_ms) or suppression_ms < 0:
            raise ValueError("invalid suppression_ms")
        if not isinstance(enable_explanations, bool):
            raise ValueError("invalid enable_explanations")
        rules: list = []
        if enable_explanations:
            raw_rules = [] if suppression_rules is None else suppression_rules
            if not isinstance(raw_rules, list):
                raise ValueError("invalid suppression rules")
            seen_rule_ids: set = set()
            rules = [_validate_suppression_rule(raw, seen_rule_ids) for raw in raw_rules]

        self._downsample_ms = downsample_ms
        self._suppression_ms = suppression_ms
        self._enable_explanations = enable_explanations
        self._rules = rules
        self._registry = ExplanationRegistry() if registry is None else registry
        self._window_engine = WindowSuppressionEngine()
        if window_suppression_rules is not None:
            self._window_engine.set_rules(window_suppression_rules)
        # Maintenance-window configuration is validated up front; reset()
        # clears data but keeps it, exactly like the window rules above.
        self._maintenance_windows = _validate_maintenance_windows(maintenance_windows)
        self.reset()

    def reset(self) -> None:
        """Drop all applied batches, samples, windows and alerts."""
        self._batches: dict = {}  # batch_id -> batch record
        self._retracted: set = set()  # batch_ids in the terminal retracted state
        # Each point keeps one candidate per contributing batch rank so that
        # retracting the winning batch can restore the next-highest rank.
        self._points: dict = {}  # point_key -> {rank: metric}
        self._bucket_points: dict = {}  # bucket_key -> set of point_key
        self._buckets: dict = {}  # bucket_key -> {sum, count, sources}
        self._alerts: list = []
        self._alert_ids: set = set()
        self._registry.clear()
        # Recorded window-suppression episodes are state, the configured rules
        # are not: reset clears the former and keeps the latter.
        self._window_engine.reset()

    # -- validation ---------------------------------------------------------

    def _validate_sample(self, raw: Any) -> dict:
        if not isinstance(raw, dict):
            raise BatchError(400, "metric_batch_invalid", "invalid metric")
        # A sample whose timestamp is not a usable epoch-millis value cannot be
        # assigned to any downsample window; it must not be dropped silently.
        if not _valid_timestamp(raw.get("timestamp_ms")):
            raise BatchError(422, "metric_window_unresolved", "metric window unresolved")
        try:
            return _validate_metric(raw)
        except ValueError as exc:
            raise BatchError(400, "metric_batch_invalid", str(exc)) from exc

    # -- batch application --------------------------------------------------

    def apply_batch(self, request: dict) -> dict:
        """Apply one metric batch, or delegate legacy requests to ``process``.

        A request without ``batch_id`` is handled by the original stateless
        entry point with unchanged behavior. With ``batch_id`` the batch is
        validated as a whole, deduplicated by content, and merged into the
        stored streams; affected windows are recomputed immediately.
        """
        if not isinstance(request, dict):
            raise BatchError(400, "metric_batch_invalid", "invalid request")
        batch_id = request.get("batch_id")
        if batch_id is None:
            return process(request)
        if not (isinstance(batch_id, str) and batch_id != ""):
            raise BatchError(400, "metric_batch_invalid", "invalid batch_id")

        # Per-query source failover is never part of a batch: applying (or
        # retracting) a batch must neither persist nor silently accept it.
        if "source_priority" in request:
            raise BatchError(400, "metric_batch_invalid", "invalid source_priority")

        max_event_time_ms = request.get("max_event_time_ms")
        if not _valid_timestamp(max_event_time_ms):
            raise BatchError(400, "metric_batch_invalid", "invalid max_event_time_ms")

        # Optional window-suppression reconfiguration: validated up front and
        # applied only once the whole batch has been accepted, taking effect
        # before this batch's events are recorded.
        raw_window_rules = request.get("window_suppression_rules")
        validated_window_rules: list | None = None
        if raw_window_rules is not None:
            validated_window_rules = _validate_window_rules(raw_window_rules)

        raw_metrics = request.get("metrics")
        if not isinstance(raw_metrics, list):
            raise BatchError(400, "metric_batch_invalid", "invalid request")
        metrics = [self._validate_sample(raw) for raw in raw_metrics]

        raw_alerts = request.get("alerts", [])
        if raw_alerts is None:
            raw_alerts = []
        if not isinstance(raw_alerts, list):
            raise BatchError(400, "metric_batch_invalid", "invalid request")
        seen_ids: set = set()
        alerts = []
        for raw in raw_alerts:
            try:
                alerts.append(_validate_alert(raw, seen_ids))
            except ValueError as exc:
                raise BatchError(400, "metric_batch_invalid", str(exc))
        if any(alert["alert_id"] in self._alert_ids for alert in alerts):
            raise BatchError(400, "metric_batch_invalid", "duplicate alert_id")

        if metrics:
            if self._downsample_ms is None:
                raise BatchError(422, "metric_window_unresolved", "metric window unresolved")
            window_start = (max_event_time_ms // self._downsample_ms) * self._downsample_ms
            for metric in metrics:
                timestamp_ms = metric["timestamp_ms"]
                if timestamp_ms < window_start or timestamp_ms > max_event_time_ms:
                    raise BatchError(
                        400, "metric_batch_range_invalid", "metric batch range invalid"
                    )

        fingerprint = _batch_fingerprint(max_event_time_ms, metrics, alerts)
        known = self._batches.get(batch_id)
        if known is not None:
            if known["fingerprint"] == fingerprint:
                # Full duplicate: report success with nothing re-applied.
                return {
                    "batch_id": batch_id,
                    "status": BATCH_APPLIED,
                    "affected_streams": 0,
                    "recomputed_windows": 0,
                }
            raise BatchError(409, "metric_batch_conflict", "metric batch conflict")
        # A retracted batch left no contributions behind, so re-applying the
        # same batch_id is a fresh application (the typical patch flow: retract
        # the faulty batch, then resubmit its correction under the same id).

        rank = (max_event_time_ms, batch_id)
        # Within one batch, identical points dedupe with the later one winning.
        batch_points: dict = {}
        for metric in metrics:
            point_key = (
                metric["source"],
                metric["name"],
                _canonical_labels(metric["labels"]),
                metric["timestamp_ms"],
            )
            batch_points[point_key] = metric

        affected_streams: set = set()
        affected_buckets: set = set()
        for point_key, metric in batch_points.items():
            candidates = self._points.setdefault(point_key, {})
            if rank in candidates:
                # Same rank tuple cannot occur for a different batch_id (the
                # batch_id is part of the rank) and duplicate batches were
                # handled above; nothing to merge in that case.
                continue
            winning_before = max(candidates) if candidates else None
            candidates[rank] = metric
            labels_key = point_key[2]
            start = (point_key[3] // self._downsample_ms) * self._downsample_ms
            bucket_key = (point_key[1], labels_key, start)
            self._bucket_points.setdefault(bucket_key, set()).add(point_key)
            if winning_before is None or rank > winning_before:
                # Only a newly winning value changes the aggregate/stream.
                affected_streams.add((point_key[1], labels_key))
                affected_buckets.add(bucket_key)

        for bucket_key in affected_buckets:
            self._recompute_bucket(bucket_key)

        self._batches[batch_id] = {
            "fingerprint": fingerprint,
            "rank": rank,
            "points": batch_points,
            "alerts": alerts,
        }
        self._retracted.discard(batch_id)
        self._alerts.extend(alerts)
        self._alert_ids.update(alert["alert_id"] for alert in alerts)

        if validated_window_rules is not None:
            self._window_engine.set_rules(validated_window_rules)
        if self._window_engine.rules:
            # Window-suppression episodes follow the event stream as observed;
            # retraction does not rewrite this history.
            _feed_window_events(
                self._window_engine, list(batch_points.values()), alerts
            )

        return {
            "batch_id": batch_id,
            "status": BATCH_APPLIED,
            "affected_streams": len(affected_streams),
            "recomputed_windows": len(affected_buckets),
        }

    def _point_winner(self, point_key: tuple) -> tuple | None:
        """Return ``(rank, metric)`` of the highest-rank candidate, if any."""
        candidates = self._points.get(point_key)
        if not candidates:
            return None
        rank = max(candidates)
        return rank, candidates[rank]

    def _recompute_bucket(self, bucket_key: tuple) -> None:
        bucket = _new_bucket()
        live_points = set()
        for point_key in self._bucket_points[bucket_key]:
            winner = self._point_winner(point_key)
            if winner is None:
                continue
            live_points.add(point_key)
            _rank, metric = winner
            _bucket_add(bucket, metric["source"], metric["timestamp_ms"], metric["value"])
        if bucket["count"] == 0:
            # No winning samples remain: the window disappears from queries.
            self._bucket_points.pop(bucket_key, None)
            self._buckets.pop(bucket_key, None)
            return
        self._bucket_points[bucket_key] = live_points
        self._buckets[bucket_key] = bucket

    # -- batch retraction ---------------------------------------------------

    def retract_batch(self, batch_id: Any) -> dict:
        """Retract a previously applied batch and correct the current state.

        The batch's deduplicated points and alerts stop contributing. Points
        shared with other batches re-resolve to the highest remaining batch
        rank; affected windows recompute under the same rank semantics. A
        second retraction of the same id is an idempotent no-op that still
        reports ``retracted`` with zero counts.
        """
        if not (isinstance(batch_id, str) and batch_id != ""):
            raise BatchError(
                400, "metric_batch_retract_invalid", "invalid batch_id"
            )
        if batch_id in self._retracted:
            return {
                "batch_id": batch_id,
                "status": BATCH_RETRACTED,
                "removed_metrics": 0,
                "removed_alerts": 0,
                "affected_streams": 0,
                "recomputed_windows": 0,
            }
        record = self._batches.get(batch_id)
        if record is None:
            raise BatchError(404, "metric_batch_not_found", "metric batch not found")

        rank = record["rank"]
        batch_points = record["points"]
        alerts = record["alerts"]

        # Identify every window the batch contributed candidates to and
        # snapshot its aggregate. Everything below is in-memory bookkeeping
        # that cannot fail, so retraction either commits fully or (on the
        # validation failures above) never starts.
        affected_buckets: set = set()
        for point_key in batch_points:
            labels_key = point_key[2]
            start = (point_key[3] // self._downsample_ms) * self._downsample_ms
            affected_buckets.add((point_key[1], labels_key, start))

        before_windows = {
            bucket_key: self._window_value(bucket_key) for bucket_key in affected_buckets
        }

        for point_key in batch_points:
            candidates = self._points.get(point_key)
            if candidates is None or rank not in candidates:
                continue
            del candidates[rank]
            if not candidates:
                self._points.pop(point_key, None)

        for alert in alerts:
            try:
                self._alerts.remove(alert)
            except ValueError:
                pass
            self._alert_ids.discard(alert["alert_id"])

        # Re-resolve winners among the remaining batch ranks. A window whose
        # higher-rank batch still covers a point keeps exactly its value; only
        # windows whose aggregate value changed (or that are cleared) count.
        changed_windows: set = set()
        for bucket_key, before in before_windows.items():
            self._recompute_bucket(bucket_key)
            if self._window_value(bucket_key) != before:
                changed_windows.add(bucket_key)

        changed_streams = {(key[0], key[1]) for key in changed_windows}

        self._batches.pop(batch_id, None)
        self._retracted.add(batch_id)

        return {
            "batch_id": batch_id,
            "status": BATCH_RETRACTED,
            "removed_metrics": len(batch_points),
            "removed_alerts": len(alerts),
            "affected_streams": len(changed_streams),
            "recomputed_windows": len(changed_windows),
        }

    def _window_value(self, bucket_key: tuple):
        """The query-visible aggregate value of a window, or None if it is gone.

        Only this value decides whether retraction changed observable output:
        count/source differences behind an identical mean change nothing.
        """
        bucket = self._buckets.get(bucket_key)
        if bucket is None:
            return None
        return round(bucket["sum"] / bucket["count"] + 0.0, 6)

    # -- queries --------------------------------------------------------------

    def query_series(
        self,
        name: str | None = None,
        labels: dict | None = None,
        start_ms: Any = None,
        end_ms: Any = None,
        aggregations: dict | None = None,
        source_quorum: dict | None = None,
        source_weights: dict | None = None,
        source_priority: dict | None = None,
    ) -> list:
        """Return current downsampled windows in the established output shape.

        Optional filters: exact metric name, label subset match, and a
        ``[start_ms, end_ms]`` range over window start times. ``aggregations``
        maps exact metric names to ``avg``/``min``/``max``/``sum``/``last``/
        ``median``/``p95``/``p99``; unmapped metrics keep the default ``avg``.
        ``median`` is the middle value or the mean of the two middle values
        for an even sample count; ``p95``/``p99`` use the one-based nearest
        rank ``ceil(q * n)`` without interpolation, and arrival order never
        affects the result. ``source_quorum`` maps exact
        metric names to positive integers: a window is output only when its
        deduplicated source set reaches the threshold. ``source_weights`` maps
        exact metric names to per-source weight configurations: a listed
        target merges each window as the weighted sum of its participating
        samples divided by the effective weight sum, and windows without
        effective weight are marked ``weight_missing`` with a null value.
        ``source_priority`` maps exact metric names to ordered source lists:
        a quorum-passing window of such a target uses only the first configured
        source that actually appears in the window (failover), aggregating
        that source's samples; windows with none of the configured sources are
        marked ``priority_missing`` with a null value. The same metric may not
        appear in both ``source_weights`` and ``source_priority``.
        Output rows keep the existing fields and the existing
        (name, labels, timestamp) order.
        """
        if name is not None and not isinstance(name, str):
            raise ValueError("invalid name")
        if labels is not None and not isinstance(labels, dict):
            raise ValueError("invalid labels")
        for bound in (start_ms, end_ms):
            if bound is not None and not _valid_timestamp(bound):
                raise ValueError("invalid time range")
        agg_map = _validate_aggregations(aggregations)
        quorum_map = _validate_source_quorum(source_quorum)
        weights_map = _validate_source_weights(source_weights)
        priority_map = _validate_source_priority(source_priority)
        if priority_map.keys() & weights_map.keys():
            raise ValueError("invalid source_priority")

        rows = []
        for (bucket_name, labels_key, start), bucket in self._buckets.items():
            if name is not None and bucket_name != name:
                continue
            bucket_labels = json.loads(labels_key)
            if labels is not None and any(
                bucket_labels.get(key) != value for key, value in labels.items()
            ):
                continue
            if start_ms is not None and start < start_ms:
                continue
            if end_ms is not None and start > end_ms:
                continue
            # Coverage is the size of the full deduplicated winning-sample
            # source set, recomputed from current winners after every patch or
            # retraction — not the sample or request count.
            if (
                bucket_name in quorum_map
                and len(bucket["sources"]) < quorum_map[bucket_name]
            ):
                continue
            weights = weights_map.get(bucket_name)
            if weights is not None:
                rows.append(_weighted_row(bucket_name, labels_key, start, bucket, weights))
                continue
            priorities = priority_map.get(bucket_name)
            if priorities is not None:
                rows.append(
                    _priority_row(
                        bucket_name,
                        labels_key,
                        start,
                        bucket,
                        priorities,
                        agg_map.get(bucket_name, "avg"),
                    )
                )
                continue
            rows.append(
                {
                    "name": bucket_name,
                    "labels": bucket_labels,
                    "timestamp_ms": start,
                    "value": _bucket_value(bucket, agg_map.get(bucket_name, "avg")),
                    "count": bucket["count"],
                    "sources": sorted(bucket["sources"]),
                }
            )
        rows.sort(key=lambda row: (row["name"], _canonical_labels(row["labels"]), row["timestamp_ms"]))
        return rows

    # -- window suppression rules --------------------------------------------

    def set_window_suppression_rules(self, rules: list | None) -> None:
        """Replace the time-window suppression rule set (all or nothing).

        The new configuration governs events arriving after this call;
        changing durations never retroactively alters recorded hits, and
        removing a rule only stops future matching — its recorded states stay
        queryable by rule_id.
        """
        self._window_engine.set_rules(rules)

    def query_suppression_states(
        self,
        rule_id: str | None = None,
        source: str | None = None,
        labels: dict | None = None,
        now_ms: Any = None,
    ) -> list:
        """Return recorded window-suppression states (see ``WindowSuppressionEngine.query``)."""
        return self._window_engine.query(
            rule_id=rule_id, source=source, labels=labels, now_ms=now_ms
        )

    # -- maintenance windows ---------------------------------------------------

    @property
    def maintenance_windows(self) -> list:
        """The configured maintenance windows (defensive copies)."""
        return [
            dict(window, labels=dict(window["labels"]) if window["labels"] is not None else None)
            for window in self._maintenance_windows
        ]

    def set_maintenance_windows(self, windows: list | None) -> None:
        """Replace the maintenance-window configuration (all or nothing).

        Validation is fully completed before anything is replaced, so a
        rejected configuration leaves the previous one untouched. ``None``
        clears the configuration.
        """
        self._maintenance_windows = _validate_maintenance_windows(windows)

    def query_alerts(self) -> dict:
        """Re-adjudicate all stored alerts against the current configuration.

        Suppression is recomputed on every query, so corrections that change
        the stored alert set are reflected in subsequent results.
        """
        alerts = list(self._alerts)
        window_suppressed_ids = {
            alert["alert_id"]
            for alert in alerts
            if self._window_engine.is_suppressed(
                alert["source"], alert["name"], alert["labels"], alert["timestamp_ms"]
            )
        }
        # Maintenance windows are re-evaluated against the current alert set
        # on every query, so late corrections and retractions are reflected.
        extra_suppressed_ids = window_suppressed_ids | _maintenance_suppressed_ids(
            alerts, self._maintenance_windows
        )
        if self._enable_explanations:
            result = _process_with_explanations(
                alerts, self.query_series(), self._rules, self._registry
            )
            if extra_suppressed_ids:
                for output_alert in result["alerts"]:
                    if output_alert["alert_id"] in extra_suppressed_ids:
                        output_alert["status"] = "suppressed"
                merged_ids = set(result["suppressed_alert_ids"]) | extra_suppressed_ids
                result["suppressed_alert_ids"] = [
                    output_alert["alert_id"]
                    for output_alert in result["alerts"]
                    if output_alert["alert_id"] in merged_ids
                ]
            return result
        result_alerts, suppressed_alert_ids = _suppress_alerts(alerts, self._suppression_ms)
        if extra_suppressed_ids:
            for entry in result_alerts:
                if entry["alert_id"] in extra_suppressed_ids:
                    entry["suppressed"] = True
            suppressed_alert_ids = [
                entry["alert_id"] for entry in result_alerts if entry["suppressed"]
            ]
        return {"alerts": result_alerts, "suppressed_alert_ids": suppressed_alert_ids}
