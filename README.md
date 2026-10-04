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

## 指标批次补丁与迟到修正（有状态服务）

`MetricBatchService` 在内存中维护指标流状态，接受带批次标识的指标样本批次，支持幂等应用与迟到数据修正；不增加任何落盘文件或持久化入口。

```python
from metric_fusion import MetricBatchService, BatchError

service = MetricBatchService(downsample_ms=60000, suppression_ms=30000)
result = service.apply_batch({
    "batch_id": "batch-001",
    "max_event_time_ms": 119000,
    "metrics": [
        {"source": "agent-a", "name": "cpu.usage",
         "labels": {"host": "db-1"}, "timestamp_ms": 61000, "value": 0.5},
    ],
})
# => {"batch_id": "batch-001", "status": "applied",
#     "affected_streams": 1, "recomputed_windows": 1}
```

- 批次样本沿用既有指标字段（`source/name/labels/timestamp_ms/value`）与校验；批次另需 `batch_id`（非空字符串）与 `max_event_time_ms`。未提供 `batch_id` 的请求按原有 `process` 入口的原方式处理，行为完全不变。
- 样本时间戳必须落在批次窗口内：`[max_event_time_ms // downsample_ms * downsample_ms, max_event_time_ms]`，否则整批拒绝，HTTP 400，`code` 固定为 `metric_batch_range_invalid`。
- 时间戳不可用（非数值、非有限、为负）或服务未配置 `downsample_ms` 时，样本归属窗口无法确定，整批拒绝，HTTP 422，`code` 固定为 `metric_window_unresolved`，样本不会被静默丢弃。
- 幂等：同一 `batch_id` 重复到达且内容（样本集合与最大事件时间，与样本顺序无关）相同，视为成功，返回相同状态 `applied`，但 `affected_streams` 与 `recomputed_windows` 均为 0；内容不同则整批拒绝，HTTP 409，`code` 固定为 `metric_batch_conflict`。
- 应用成功返回 `batch_id`、`status`（`applied`）、`affected_streams`（受影响的 `name + 规范 labels` 流数量）、`recomputed_windows`（重算的降采样窗口数量）。迟到样本落入已查询过的窗口时，该窗口立即按当前样本集重算，后续查询返回修正值。
- 跨批次同一数据点（`source/name/labels/timestamp_ms`）冲突按批次秩 `(max_event_time_ms, batch_id)` 确定胜者，与到达顺序无关；因此批次到达顺序不影响最终聚合值，同一输入集合重复执行结果相同。
- 其他校验失败（结构、字段、重复 `alert_id` 等）返回 HTTP 400，`code` 为 `metric_batch_invalid`，`message` 沿用既有校验消息。所有失败均为整批拒绝，不产生部分效果。

### 批次撤回

`service.retract_batch(batch_id)`（及 `POST /v1/metric_batches/{batch_id}/retract`）撤回一个已应用批次，用于批次补丁与迟到修正。撤回按该批次**去重后的规范数据点和规范告警**移除贡献：

- 同一 `batch_id` 重复应用后只撤回一次；撤回后再撤回同一 `batch_id` 仍返回 `status="retracted"`，但 `removed_metrics`、`removed_alerts`、`affected_streams`、`recomputed_windows` 均为 0，状态不再变化。
- 同一数据点撤回后，按剩余批次的批次秩 `(max_event_time_ms, batch_id)` 重新确定胜者：若更高秩批次仍覆盖该点，其值保持不变；否则恢复剩余最高秩批次的值。同窗口其他样本也按既有批次秩语义稳定重算，到达顺序仍不影响结果。
- 响应字段：
  - `removed_metrics` / `removed_alerts`：该批次去重后的数据点数 / 告警数（幂等再次撤回时为 0）。
  - `affected_streams`：聚合值发生变化或窗口被清空的 `name + 规范 labels` 流数量；仅撤回了落败批次、聚合值不变的流不计入。
  - `recomputed_windows`：聚合值发生变化（含被清空）的降采样窗口数量。
- 撤回后 `query_series`、`query_alerts` 以及 HTTP 全量/筛选查询都返回修正后的当前状态；告警仍按 `suppression_ms`、级别突破与排序重新裁决，`suppressed_alert_ids` 随之更新（例如撤回抑制者后，原被抑制告警恢复为 active）。
- 典型补丁流程：撤回有问题的批次后，可以用同一 `batch_id` 重新提交修正内容，作为一次全新应用生效。
- 错误：`batch_id` 不是非空字符串（含路径结构无法识别）返回 HTTP 400，`code` 固定为 `metric_batch_retract_invalid`；`batch_id` 从未应用返回 HTTP 404，`code` 固定为 `metric_batch_not_found`。任何撤回失败都原子拒绝，不会部分删除数据或改动批次状态。


查询（结果始终反映当前状态，排序与窗口边界与既有输出一致）：

```python
service.query_series(name="cpu.usage", labels={"host": "db-1"},
                     start_ms=0, end_ms=119000)   # 过滤均可省略
service.query_alerts()   # 对当前已存告警重新裁决抑制，修正后结果随之变化
```

批次可附带 `alerts`（沿用既有告警校验），服务累积存储并在每次 `query_alerts()` 时重新裁决，因此修正后不再满足抑制条件的结果会反映在后续查询中。`service.reset()` 清空全部状态。

HTTP 服务（仅内存状态）：

```bash
python -m metric_fusion.server --port 8080 --downsample-ms 60000 --suppression-ms 30000
```

- `POST /v1/metric_batches`：应用批次（无 `batch_id` 时按旧版处理）；`POST /v1/metric_batches/{batch_id}/retract`：撤回批次（请求体可空，若有则须为可识别 JSON）。错误响应为 `{"code": ..., "message": ...}`，状态码如上。
- `POST /process`：旧版无状态入口。`POST /v1/query`：按 `name/labels/start_ms/end_ms` 查询 series。`GET /v1/series`、`GET /v1/alerts`：全量查询。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
