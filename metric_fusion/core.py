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


# ---------------------------------------------------------------------------
# Metric batch patches and late-data correction
# ---------------------------------------------------------------------------

BATCH_APPLIED = "applied"


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
        self.reset()

    def reset(self) -> None:
        """Drop all applied batches, samples, windows and alerts."""
        self._batches: dict = {}  # batch_id -> content fingerprint
        self._points: dict = {}  # point_key -> (rank, metric)
        self._bucket_points: dict = {}  # bucket_key -> set of point_key
        self._buckets: dict = {}  # bucket_key -> {sum, count, sources}
        self._alerts: list = []
        self._alert_ids: set = set()
        self._registry.clear()

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

        max_event_time_ms = request.get("max_event_time_ms")
        if not _valid_timestamp(max_event_time_ms):
            raise BatchError(400, "metric_batch_invalid", "invalid max_event_time_ms")

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
            if known == fingerprint:
                # Full duplicate: report success with nothing re-applied.
                return {
                    "batch_id": batch_id,
                    "status": BATCH_APPLIED,
                    "affected_streams": 0,
                    "recomputed_windows": 0,
                }
            raise BatchError(409, "metric_batch_conflict", "metric batch conflict")

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
            existing = self._points.get(point_key)
            if existing is not None and existing[0] >= rank:
                continue  # a newer-or-equal batch already owns this point
            self._points[point_key] = (rank, metric)
            labels_key = point_key[2]
            start = (point_key[3] // self._downsample_ms) * self._downsample_ms
            bucket_key = (point_key[1], labels_key, start)
            self._bucket_points.setdefault(bucket_key, set()).add(point_key)
            affected_streams.add((point_key[1], labels_key))
            affected_buckets.add(bucket_key)

        for bucket_key in affected_buckets:
            self._recompute_bucket(bucket_key)

        self._batches[batch_id] = fingerprint
        self._alerts.extend(alerts)
        self._alert_ids.update(alert["alert_id"] for alert in alerts)

        return {
            "batch_id": batch_id,
            "status": BATCH_APPLIED,
            "affected_streams": len(affected_streams),
            "recomputed_windows": len(affected_buckets),
        }

    def _recompute_bucket(self, bucket_key: tuple) -> None:
        bucket = {"sum": 0.0, "count": 0, "sources": set()}
        for point_key in self._bucket_points[bucket_key]:
            _rank, metric = self._points[point_key]
            bucket["sum"] += metric["value"]
            bucket["count"] += 1
            bucket["sources"].add(metric["source"])
        self._buckets[bucket_key] = bucket

    # -- queries --------------------------------------------------------------

    def query_series(
        self,
        name: str | None = None,
        labels: dict | None = None,
        start_ms: Any = None,
        end_ms: Any = None,
    ) -> list:
        """Return current downsampled windows in the established output shape.

        Optional filters: exact metric name, label subset match, and a
        ``[start_ms, end_ms]`` range over window start times. Output rows keep
        the existing fields and the existing (name, labels, timestamp) order.
        """
        if name is not None and not isinstance(name, str):
            raise ValueError("invalid name")
        if labels is not None and not isinstance(labels, dict):
            raise ValueError("invalid labels")
        for bound in (start_ms, end_ms):
            if bound is not None and not _valid_timestamp(bound):
                raise ValueError("invalid time range")

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
            mean = bucket["sum"] / bucket["count"] + 0.0  # normalize -0.0
            rows.append(
                {
                    "name": bucket_name,
                    "labels": bucket_labels,
                    "timestamp_ms": start,
                    "value": round(mean, 6),
                    "count": bucket["count"],
                    "sources": sorted(bucket["sources"]),
                }
            )
        rows.sort(key=lambda row: (row["name"], _canonical_labels(row["labels"]), row["timestamp_ms"]))
        return rows

    def query_alerts(self) -> dict:
        """Re-adjudicate all stored alerts against the current configuration.

        Suppression is recomputed on every query, so corrections that change
        the stored alert set are reflected in subsequent results.
        """
        alerts = list(self._alerts)
        if self._enable_explanations:
            return _process_with_explanations(
                alerts, self.query_series(), self._rules, self._registry
            )
        result_alerts, suppressed_alert_ids = _suppress_alerts(alerts, self._suppression_ms)
        return {"alerts": result_alerts, "suppressed_alert_ids": suppressed_alert_ids}
