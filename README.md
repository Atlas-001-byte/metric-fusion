# Metric Fusion

可观测性指标汇聚服务：多源指标归并、降采样与告警抑制。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。

## 状态

初始基线：只有本说明，尚无实现。

## 用法

库接口：

```python
from metric_fusion import process
result = process(request)  # request/result 均为 UTF-8 JSON 对应的 dict
```

命令行：

```bash
python -m metric_fusion request.json > result.json
python -m metric_fusion --serve [--host 127.0.0.1] [--port 8080]  # 见下文 HTTP 适配
```

成功退出码为 0；失败时把异常信息写入标准错误并以退出码 2 结束。

## 行为

- 指标按 `source/name/labels/timestamp_ms` 去重（后覆盖先），以 `name + 规范 labels`（labels 键排序）为序列键。
- 同桶（桶起点为 `timestamp_ms // downsample_ms * downsample_ms`）跨 source 取均值，收集去重来源，输出桶起点、`round(value, 6)` 的均值、样本数与来源；series 按 name、规范 labels、timestamp_ms 排序。
- 告警按 `rule + 序列键` 分组，组内按 timestamp_ms、alert_id 排序：首条发出；距最近发出不超过 `suppression_ms` 且级别不更高者抑制；更高级别重置起点并发出。输出各告警的 `alert_id/severity/suppressed` 及 `suppressed_alert_ids`。
- 校验错误消息：`invalid request`、`invalid metric`、`invalid value`、`invalid alert`、`invalid severity`、`duplicate alert_id`、`invalid downsample_ms`、`invalid suppression_ms`、`invalid JSON`。

## 抑制解释（可选开启）

请求中加 `"enable_explanations": true`（默认 `false`）与 `suppression_rules` 后启用。默认关闭时输出、抑制结果与异常行为与上述基线完全一致，且不会读取或校验规则配置。

规则形如：

```json
{
  "rule_id": "disk-flap",
  "selector": {"metric": "disk.*", "labels": {"host": "db-1"}},
  "min_severity": "warning",
  "suppression_ms": 60000
}
```

- `selector.metric`：精确指标名，或含 `*` 的通配；`selector.labels` 为标签等值条件，需全部命中。
- `min_severity` 取 `info/warning/critical`；事件级别低于它时规则不命中。`suppression_ms` 为非负整数。
- 同一批次先按指标名、完整标签集与触发时间整理告警，再按规则裁决：事件被某条规则命中，且同一指标存在更早的有效告警（active）、其时间差不超过该规则时长时，该事件 `status` 为 `suppressed`，否则为 `active`；未命中抑制不产生解释。
- 多规则同时命中时，标签命中条件数更多者优先；其次指标选择器更精确（精确名 > 通配 > `*`）；完全相同时取 `rule_id` 字典序最小者。
- 同指纹（指标名 + 规范标签集 + 触发时间的 SHA-256）重复触发沿用既有去重与裁决语义：同时间点更高级别仍会突破。解释不改变原告警字段与顺序。
- 开启时每条告警保留全部原字段，并附 `fingerprint` 与 `status`；响应新增 `explanations`，每条含 `suppressed_fingerprint`、`suppressor_fingerprint`、`rule_id`、`started_at`、`expires_at`。

查询（独立于处理入口）：

```python
from metric_fusion import query_explanations
query_explanations(fingerprint="...")          # 按告警指纹
query_explanations(rule_id="disk-flap")        # 按规则
query_explanations(fingerprint="...", now_ms=60000)  # 指定当前时间
```

- 抑制未结束的记录不含 `ended_at`；`now_ms >= expires_at`（默认取当前墙钟时间，单位毫秒）后查询补上 `ended_at = expires_at`。
- 不存在的指纹或 `rule_id` 返回 `[]`，不抛异常。
- 另有 `ExplanationRegistry`（可传给 `process(..., registry=)` 以隔离状态）与 `reset_explanations()`。
- 开启模式下的新增校验错误：`invalid suppression rules`、`invalid suppression rule`、`invalid rule_id`、`duplicate rule_id`、`invalid selector`、`invalid enable_explanations`。任何校验失败均抛 `ValueError` 且本次处理不产生任何输出或解释记录。

## 指标批次补丁与迟到数据修正

在上述无状态 `process` 入口之外，新增有状态的批次入口（内存态，不额外落盘、不新增持久化入口）：

```python
from metric_fusion import MetricStore, apply_metric_batch, query_series, query_batch_alerts

store = MetricStore(downsample_ms=1000, suppression_ms=5000)
receipt = store.apply_batch({
    "batch_id": "batch-0001",
    "max_event_time_ms": 10000,
    "metrics": [{"source": "s1", "name": "cpu.usage", "labels": {"host": "a"},
                 "timestamp_ms": 100, "value": 3.0}],
    "alerts": [],
})
store.query_series(name="cpu.usage", start_ms=0, end_ms=60000)
store.query_alerts()
```

- 批次样本沿用既有指标身份（source/name/labels）、归并键、降采样窗口（`timestamp_ms // downsample_ms * downsample_ms`）、跨 source 取均值与告警抑制语义；同身份点仍以后覆盖先。
- 已识别批次（含非空字符串 `batch_id`）必须带 `max_event_time_ms`（有限非负数，毫秒）。窗口网格取构造参数 `downsample_ms`；未配置时批次可自带 `downsample_ms`，网格一经确定不得更改（不同值报 `invalid downsample_ms`）。
- **幂等**：同一 `batch_id` 重复到达只生效一次。重复批次与首次内容（样本、告警、水位，顺序无关）完全一致时返回 `status="already_applied"`、两个数量均为 0，视为成功；内容不同则整批拒绝，抛 `BatchError(code="metric_batch_conflict")`，对应 HTTP 409。
- **区间校验**：样本时间戳晚于 `max_event_time_ms` 时整批拒绝，`code="metric_batch_range_invalid"`，HTTP 400（时间戳按地板网格必不早于窗口起点）。
- **归属窗口不可静默丢弃**：有样本但无法确定网格（未配置且批次未携带）时整批拒绝，`code="metric_window_unresolved"`，HTTP 422；仅告警批次不受此限。
- 三类批次错误都是 `BatchError`（`ValueError` 子类），`.http_status` 给出状态码；形状/类型错误仍为普通 `ValueError`（如 `invalid batch_id`、`invalid max_event_time_ms`）。任何拒绝都是原子的，不产生部分写入。
- **迟到修正**：补丁只重算样本落入的窗口（回执 `recomputed_windows` 即去重窗口数，`affected_streams` 为受影响指标流数），随后在合并后的全量数据上重新裁决告警；曾被抑制的告警可能变为发出，开启解释模式时过时解释记录同步撤销。之后 `query_series` / `query_alerts` 返回修正结果，与批次到达顺序无关，同一输入集合结果确定。
- 查询：`query_series(name=None, labels=None, start_ms=None, end_ms=None)`（标签为等值包含条件，时间按窗口起点、闭区间）按 name、规范 labels、窗口起点排序，输出字段与基线一致；`query_alerts()` 返回当前抑制裁决；开启解释的 store 另有 `query_explanations(...)`。`reset()` 清空全部内存状态。
- 另有进程级默认 store 便捷函数：`apply_metric_batch`、`query_series`、`query_batch_alerts`、`reset_batches`。
- 未提供 `batch_id` 时仍走原有批次方式：`max_event_time_ms` 可省，缺失网格按原规则报 `invalid downsample_ms`，不做幂等记录；旧版指标批次与原 `process` 入口的输入、输出、异常完全不变。

### HTTP 适配

`metric_fusion/server.py` 提供仅依赖标准库的薄适配层（单实例、内存态），`POST /batches` 提交批次，`GET /series`（参数 `name`、`labels=<JSON>`、`start_ms`、`end_ms`）与 `GET /alerts` 查询：

```bash
python -m metric_fusion --serve --host 127.0.0.1 --port 8080
# 可选环境变量 METRIC_FUSION_DOWNSAMPLE_MS / METRIC_FUSION_SUPPRESSION_MS 预置网格
```

成功回执：`{"batch_id": ..., "status": "applied" | "already_applied", "affected_streams": N, "recomputed_windows": N}`；拒绝响应为 `{"code": "metric_batch_conflict" | "metric_batch_range_invalid" | "metric_window_unresolved"}`，状态码分别为 409/400/422。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
