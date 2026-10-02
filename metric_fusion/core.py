"""核心逻辑：指标归并、降采样与告警抑制。"""

import math

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


def _is_plain_int(value):
    """整数且非布尔。"""
    return isinstance(value, int) and not isinstance(value, bool)


def _non_empty_str(value):
    return isinstance(value, str) and value != ""


def _canonical_labels(labels, error_message):
    """校验 labels 并返回规范形式（键排序的元组、字典）。"""
    if not isinstance(labels, dict):
        raise ValueError(error_message)
    items = []
    for key, value in labels.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError(error_message)
        items.append((key, value))
    items.sort(key=lambda kv: kv[0])
    return tuple(items), dict(items)


def _validate_metric(entry):
    if not isinstance(entry, dict):
        raise ValueError("invalid metric")
    if not _non_empty_str(entry.get("source")) or not _non_empty_str(entry.get("name")):
        raise ValueError("invalid metric")
    labels_key, labels_canon = _canonical_labels(entry.get("labels"), "invalid metric")
    timestamp_ms = entry.get("timestamp_ms")
    if not _is_plain_int(timestamp_ms) or timestamp_ms < 0:
        raise ValueError("invalid metric")
    value = entry.get("value")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("invalid value")
    return {
        "source": entry["source"],
        "name": entry["name"],
        "labels_key": labels_key,
        "labels": labels_canon,
        "timestamp_ms": timestamp_ms,
        "value": float(value),
    }


def _validate_alert(entry):
    if not isinstance(entry, dict):
        raise ValueError("invalid alert")
    if not _non_empty_str(entry.get("source")) or not _non_empty_str(entry.get("name")):
        raise ValueError("invalid alert")
    if not _non_empty_str(entry.get("alert_id")) or not _non_empty_str(entry.get("rule")):
        raise ValueError("invalid alert")
    labels_key, _ = _canonical_labels(entry.get("labels"), "invalid alert")
    timestamp_ms = entry.get("timestamp_ms")
    if not _is_plain_int(timestamp_ms) or timestamp_ms < 0:
        raise ValueError("invalid alert")
    severity = entry.get("severity")
    if severity not in SEVERITY_ORDER:
        raise ValueError("invalid severity")
    return {
        "source": entry["source"],
        "name": entry["name"],
        "labels_key": labels_key,
        "alert_id": entry["alert_id"],
        "rule": entry["rule"],
        "timestamp_ms": timestamp_ms,
        "severity": severity,
    }


def _fuse_metrics(metrics, downsample_ms):
    # (序列键, source, timestamp) 去重，后覆盖先
    samples = {}
    series_meta = {}
    for metric in metrics:
        m = _validate_metric(metric)
        series_key = (m["name"], m["labels_key"])
        series_meta.setdefault(series_key, m["labels"])
        samples[(series_key, m["source"], m["timestamp_ms"])] = m["value"]

    # (序列键, 桶起点) -> 桶内样本
    buckets = {}
    for (series_key, source, timestamp_ms), value in samples.items():
        bucket_start = (timestamp_ms // downsample_ms) * downsample_ms
        buckets.setdefault((series_key, bucket_start), []).append((source, value))

    series_points = {}
    for (series_key, bucket_start), entries in buckets.items():
        mean_value = sum(value for _, value in entries) / len(entries)
        sources = sorted({source for source, _ in entries})
        series_points.setdefault(series_key, []).append({
            "timestamp_ms": bucket_start,
            "value": round(mean_value, 6),
            "sample_count": len(entries),
            "sources": sources,
        })

    result = []
    for name, labels_key in sorted(series_points, key=lambda k: (k[0], k[1])):
        points = sorted(series_points[(name, labels_key)], key=lambda p: p["timestamp_ms"])
        result.append({
            "name": name,
            "labels": series_meta[(name, labels_key)],
            "points": points,
        })
    return result


def _suppress_alerts(alerts, suppression_ms):
    validated = []
    seen_ids = set()
    for alert in alerts:
        a = _validate_alert(alert)
        if a["alert_id"] in seen_ids:
            raise ValueError("duplicate alert_id")
        seen_ids.add(a["alert_id"])
        validated.append(a)

    groups = {}
    for index, a in enumerate(validated):
        group_key = (a["rule"], a["name"], a["labels_key"])
        groups.setdefault(group_key, []).append((index, a))

    # 抑制状态按 (rule, name, 规范 labels) 分组维护，结果按输入顺序回填
    results = [None] * len(validated)
    for members in groups.values():
        members.sort(key=lambda item: (item[1]["timestamp_ms"], item[1]["alert_id"]))
        last_emitted_ts = None
        last_emitted_level = None
        for index, a in members:
            level = SEVERITY_ORDER[a["severity"]]
            suppressed = (
                last_emitted_ts is not None
                and level <= last_emitted_level
                and a["timestamp_ms"] - last_emitted_ts <= suppression_ms
            )
            if not suppressed:
                # 发出（含更高级别重置）：窗口起点与基准级别重置
                last_emitted_ts = a["timestamp_ms"]
                last_emitted_level = level
            results[index] = {
                "alert_id": a["alert_id"],
                "severity": a["severity"],
                "suppressed": suppressed,
            }
    suppressed_ids = [r["alert_id"] for r in results if r["suppressed"]]
    return results, suppressed_ids


def process(request: dict) -> dict:
    """处理一次归并/降采样/抑制请求，返回结果字典。"""
    if not isinstance(request, dict):
        raise ValueError("invalid request")

    metrics = request.get("metrics", [])
    alerts = request.get("alerts", [])
    if not isinstance(metrics, list) or not isinstance(alerts, list):
        raise ValueError("invalid request")

    downsample_ms = request.get("downsample_ms")
    if not _is_plain_int(downsample_ms) or downsample_ms <= 0:
        raise ValueError("invalid downsample_ms")
    suppression_ms = request.get("suppression_ms")
    if not _is_plain_int(suppression_ms) or suppression_ms < 0:
        raise ValueError("invalid suppression_ms")

    series = _fuse_metrics(metrics, downsample_ms)
    alert_results, suppressed_ids = _suppress_alerts(alerts, suppression_ms)

    return {
        "series": series,
        "alerts": alert_results,
        "suppressed_alert_ids": suppressed_ids,
    }
