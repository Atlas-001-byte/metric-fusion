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

## 按指标选择窗口聚合函数（可选）

`process`、`POST /process`、`POST /v1/query` 与 `MetricBatchService.query_series` 接受可选的 `aggregations` 映射：键为精确指标名，值只能是 `avg`、`min`、`max`、`sum`、`last`、`median`、`p95`、`p99`。未命中映射的指标仍用 `avg`，未提供 `aggregations` 时行为与基线完全一致。

- 同一窗口先按既有规则得到去重样本（`source/name/labels/timestamp_ms` 后覆盖先），再计算所选函数；窗口起点为 `timestamp_ms // downsample_ms * downsample_ms`。同 `name` + 规范 labels 的窗口内：`avg/min/max/sum` 分别取平均、最小、最大、总和；`last` 取 `timestamp_ms` 最大的样本，时间相同取 `source` 字典序最大者。
- 分布型函数只看待窗口去重后的样本集合，与样本到达顺序无关（计算前排序）：`median` 在样本数为奇数时取排序后中间值，偶数时取中间两值的算术平均；`p95`、`p99` 采用一基最近秩且不插值，分别取排序后第 `ceil(0.95*n)`、第 `ceil(0.99*n)` 个样本（即单样本窗口三个函数均取该样本本身）。
- 输出字段不变（`name/labels/timestamp_ms/value/count/sources`，不增加聚合类型字段），`count` 仍是去重样本数，`sources` 去重排序，`value` 仍 `round(value, 6)` 且 `-0.0` 重新标记为 `0`（median/p95/p99 亦然）；排序不变。
- 有状态服务在补丁、迟到修正与批次撤回后按当前胜者样本重算所选函数；批次秩、幂等、`affected_streams`、`recomputed_windows`、告警重裁与顺序无关语义不变。聚合只影响选定的 series 查询：`GET /v1/series`、`GET /v1/alerts` 与告警抑制不读取该配置。
- 校验：`aggregations` 不是字符串到允许函数名的映射、键为空串或值不支持时，库调用抛 `ValueError("invalid aggregation")`；HTTP 返回 400，`{"code": "invalid_request", "message": "invalid aggregation"}`；CLI 输出该消息并以 2 退出。校验失败不部分修改状态。

## 来源法定人数过滤（可选）

`process`、`POST /v1/query` 与 `MetricBatchService.query_series` 接受可选的 `source_quorum` 映射：键为精确指标名，值为正整数阈值。去重、窗口归并与来源收集完成后，按 `name + 规范 labels + 窗口` 判断：只有窗口的**去重 sources 数量大于或等于阈值**时才输出该行。未达到阈值的窗口不进入 series，不做补点、部分输出或错误处理。未提供 `source_quorum`、或窗口指标名未命中映射时，维持现有默认聚合（`avg`）与全部窗口输出。

- 阈值按窗口的完整去重来源集判断（与 `sources` 字段同一集合），不能按样本数（`count`）或请求条数判断；`source/name/labels/timestamp_ms` 去重先于覆盖度判断。
- 可与 `aggregations` 同时使用：达到阈值的窗口仍按所选函数输出 `round(value, 6)`、`-0.0` 归一、`count`、`sources` 与既有排序；未达到阈值的窗口即使配置了聚合函数也不输出。
- 有状态服务在补丁、迟到修正或批次撤回后重新查询时，按当前胜者样本重算来源覆盖，只输出仍满足阈值的窗口；批次秩、幂等与撤回结果不受影响。
- 查询范围、`name` 与 `labels` 过滤及排序继续沿用当前口径。`GET /v1/series`、`GET /v1/alerts` 与告警抑制（含抑制解释、时间窗规则）不读取 `source_quorum`；批次应用/撤回请求也不接受该配置，其行为与响应字段不变。
- 校验：`source_quorum` 必须是字符串到正整数的映射，键非空，值不能为布尔值、零、负数或浮点数；非法时库调用抛 `ValueError("invalid source_quorum")`，HTTP `POST /v1/query` 返回 400，`{"code": "invalid_request", "message": "invalid source_quorum"}`，CLI 输出 `invalid source_quorum` 并以 2 退出。校验失败不改变已有状态。

## 按指标目标的源权重归并（可选）

`process`、`POST /v1/query` 与 `MetricBatchService.query_series` 接受可选的 `source_weights` 映射：键为精确指标名（指标目标），值为该目标的来源权重配置——`{来源: 权重}` 映射，或 `[{"source": ..., "weight": ...}]` 条目列表。未提供 `source_weights`、或指标名未命中映射时，维持现有等权重（`avg` 或所选聚合函数）行为，输出字段与形状完全不变。

```json
"source_weights": {
  "cpu.usage": {"agent-a": 2.0, "agent-b": 1.0},
  "mem.usage": [{"source": "agent-a", "weight": 1.0}, {"source": "agent-b", "weight": 0.0}]
}
```

- 去重（`source/name/labels/timestamp_ms` 后覆盖先）、窗口起点、迟到修正与批次秩语义不变；权重只在归并取值时生效。同一来源在同一窗口重复提交沿用当前去重与迟到处理语义。
- 启用权重的目标，窗口返回值为所有有效参与值按配置权重求加权和后除以有效权重之和：每个去重样本以其来源权重 `w` 贡献 `value * w` 到分子、`w` 到分母。权重为零的来源只计入可用性（出现在 `sources` 与 `count` 中）但不改变数值；未列出的来源不参与——既不贡献值也不计入 `sources`/`count`。同一目标允许少于全部已知来源参与。
- 权重目标的窗口行保留现有时间粒度、标签与序列标识及 `name/labels/timestamp_ms/value/count/sources` 字段，`value` 仍 `round(value, 6)` 且 `-0.0` 归一；权重目标不读取 `aggregations` 的函数选择，`source_quorum` 仍按完整去重来源集过滤窗口。
- 若窗口内只有权重为零的来源、有效权重之和为零，或样本均不属于配置允许的来源，该窗口不产生数值结果：`value` 为 `null` 并附 `"weight_missing": true` 标记（正常窗口行不含该字段）。窗口内没有任何样本时继续沿用现有无数据语义（不产生窗口行）。
- 有状态服务在补丁、迟到修正或批次撤回后重新查询时，按当前胜者样本重算加权结果；批次应用/撤回请求不携带该配置，批次秩、幂等、`affected_streams`、`recomputed_windows` 与告警重裁行为不变。`GET /v1/series`、`GET /v1/alerts` 与告警抑制不读取 `source_weights`。
- 校验：`source_weights` 必须是字符串到权重配置的映射，键非空；每个目标至少配置一个来源，权重为大于等于零的有限数值（不能为布尔值、负数、非有限数），同一来源不得重复配置。非法时库调用抛 `ValueError("invalid source_weights")`，HTTP `POST /v1/query` 返回 400，`{"code": "invalid_request", "message": "invalid source_weights"}`，CLI 输出 `invalid source_weights` 并以 2 退出。校验为全有或全无，失败时不加载任何部分配置、不改变已有状态。
- 样本校验沿用既有口径：缺少来源、指标目标或时间戳、数值为非有限数时抛出样本无效异常（库为 `ValueError("invalid metric")` / `ValueError("invalid value")`，批次 API 为 400 `metric_batch_invalid`）并拒绝该条样本；校验先于任何状态变更，已接受的其他样本与既有查询结果不受影响。

## 按指标来源优先级故障切换（可选）

`process`、`POST /v1/query` 与 `MetricBatchService.query_series` 接受可选的 `source_priority` 映射：键为精确指标名，值为按优先级排序的来源名数组。窗口内只采用**优先级最高且在窗口中实际出现的来源**，未命中映射的指标仍走现有（等权重或 `source_weights`）归并，未提供时行为完全不变。

```json
"source_priority": {
  "cpu.usage": ["agent-a", "agent-b", "agent-c"]
}
```

- 处理顺序：先按 `source/name/labels/timestamp_ms` 覆盖顺序去重，再按 `timestamp_ms // downsample_ms * downsample_ms` 划窗；`source_quorum` 仍用**选择前的完整去重来源集**判断（包括未列入优先级的来源）。
- 达到 quorum 阈值后，命中配置的窗口按数组顺序取**第一个在窗口中有胜者样本的来源**，只用该来源的全部去重样本按 `aggregations` 的 `avg`、`min`、`max`、`sum`、`last`、`median`、`p95`、`p99` 计算（未配置聚合函数时取 `avg`；median/p95/p99 的秩定义同上，且只在获胜来源的窗口去重样本内计算）；`last` 只在获胜来源内部取时间戳最大的样本。
- 输出沿用现有值域与命名（`name/labels/timestamp_ms/value/count/sources`）：`value` 仍 `round(value, 6)` 且 `-0.0` 归一，排序、`name/labels/start_ms/end_ms` 查询过滤不变；`count` 与 `sources` 只含最终选中来源的样本与来源（即获胜来源自身）。
- 配置的来源在窗口内均无样本时（窗口仍可因其他来源存在而通过 quorum），输出 `"value": null`、`"count": 0`、`"sources": []` 及 `"priority_missing": true`；正常行不带该字段。窗口没有任何样本时继续沿用无数据语义（不产生行）。
- 每个窗口独立故障切换：同一指标一个窗口走主来源、另一个窗口走备份来源互不影响。去重、窗口起点、迟到修正与批次秩语义不变；有状态服务在补丁、迟到修正或撤回后重新查询时按当前胜者样本重新选择来源。
- `source_priority` 与 `source_weights` 不得配置同一指标（不同指标可共存）。同一指标冲突或配置本身非法时，库调用抛 `ValueError("invalid source_priority")`；配置必须是非空指标键到非空、来源不重复的非空字符串数组的映射。
- `POST /v1/query` 返回 400 与 `{"code": "invalid_request", "message": "invalid source_priority"}`；CLI 输出 `invalid source_priority`、以 2 退出且不改变已有状态。校验为全有或全无。
- 只有 `query_series` 读取该配置：批次应用（`POST /v1/metric_batches` 中带 `batch_id` 的请求）与撤回（`POST /v1/metric_batches/{batch_id}/retract`）继续拒绝 `source_priority`（分别为 400 `metric_batch_invalid` / 400 `metric_batch_retract_invalid`，消息为 `invalid source_priority`）；幂等、批次秩、`affected_streams`、`recomputed_windows`、`GET /v1/series`、`GET /v1/alerts`、告警抑制（含解释、时间窗规则）与维护窗口保持既有行为，均不读取该配置。

## 按指标独立降采样周期（可选）

`process`、`POST /process`、`POST /v1/query` 与 `MetricBatchService.query_series` 接受可选的 `downsample_overrides` 映射：键为精确指标名，值为正整数毫秒周期。`downsample_ms` 仍是默认周期，批次接收窗口与统计口径不变；该配置只改变序列查询的窗口划分。未提供或未命中的指标行为与基线完全一致。

```json
"downsample_overrides": {"cpu.usage": 500}
```

- 样本仍按 `source/name/labels/timestamp_ms` 后覆盖先去重；命中配置的指标按 `timestamp_ms // period * period` 划窗，未命中的指标仍按 `downsample_ms` 划窗。
- `avg/min/max/sum/last/median/p95/p99`、`source_quorum`、`source_weights`、`source_priority` 与 `gap_fill` 沿用既有次序和语义；输出字段、`round(value, 6)`、`-0.0` 归一及 name、规范 labels、timestamp_ms 排序不变。
- `gap_fill` 按指标自身周期计算缺失窗口：命中 `downsample_overrides` 的指标按其周期补点，其余指标按 `downsample_ms` 补点，不同指标可有不同周期，不全局对齐。
- 有状态服务的 `query_series` 按当前批次胜者样本重算命中序列，补丁、迟到修正和撤回后反映当前结果；批次应用与撤回仍按服务构造时的 `downsample_ms` 计算范围、幂等、批次秩、`affected_streams` 和 `recomputed_windows`。
- `GET /v1/series`、`GET /v1/alerts` 与告警抑制不读取该配置。
- 校验：`downsample_overrides` 必须是精确指标名到正整数的映射，键非空，值不能为布尔值、零、负数、浮点数或非有限数。非法时库调用抛 `ValueError("invalid downsample_override")`，`POST /process` 与 `POST /v1/query` 返回 400，`{"code": "invalid_request", "message": "invalid downsample_override"}`，CLI 输出 `invalid downsample_override` 并以 2 退出。校验失败不产生部分配置或部分结果。

## 窗口缺口补点（可选）

`process`、`POST /v1/query` 与 `MetricBatchService.query_series` 接受可选的 `gap_fill` 映射：键为精确指标名，值为正整数 `max_gap_ms`。去重、窗口边界、聚合、来源权重、优先级与 `source_quorum` 全部执行完后，再在同一规范化序列（`name` + 规范 labels）的相邻**已输出**窗口之间补点，让稀疏序列有可预测的时间轴。未提供 `gap_fill` 时行为与基线完全一致。

```json
"gap_fill": {"cpu.usage": 120000}
```

- 仅当相邻两个已输出窗口的起点差减 `downsample_ms` 不超过 `max_gap_ms` 时，为中间每个缺失窗口生成一行：`timestamp_ms` 等于窗口起点，`value` 沿用前一窗口的值，`count` 为 0，`sources` 为空数组；插入后沿用现有（name、规范 labels、timestamp_ms）排序。
- 序列首窗之前、末窗之后不补；未配置 `gap_fill` 的指标不补；超过 `max_gap_ms` 的缺口不补；未达 `source_quorum` 被丢弃的窗口不能靠补点恢复（其窗口位置不生成补点行）。
- 补点只作用于 series 查询输出，不参与告警抑制，不改变 `alerts`、`suppressed_alert_ids`、抑制解释、`affected_streams` 与 `recomputed_windows`；`GET /v1/series` 与 `GET /v1/alerts` 不读取该配置。
- 有状态服务在补丁、迟到修正或撤回后重新查询时，按当前胜者样本与配置重算补点；排序、`round(value, 6)` 与 `-0.0` 归一语义不变。
- 校验：`gap_fill` 必须是精确指标名到正整数的映射，键非空，值不能为布尔值、零、负数或浮点数。非法时库调用抛 `ValueError("invalid gap_fill")`，HTTP `POST /v1/query` 返回 400，`{"code": "invalid_request", "message": "invalid gap_fill"}`，CLI 输出 `invalid gap_fill` 并以 2 退出。校验失败不部分修改状态。

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

## 时间窗抑制规则（按来源与标签维度，可选）

在请求中加入 `window_suppression_rules`（规则列表）即启用；缺省不提供时，输出、抑制结果与异常行为与上述基线完全一致，且不会读取或校验规则配置。规则由公开配置入口输入，在下一次事件进入前生效。

规则形如：

```json
{
  "rule_id": "cpu-flap",
  "source": "agent-a",
  "metric": "cpu.*",
  "labels": {"host": "db-1"},
  "pending_ms": 30000,
  "suppression_ms": 60000,
  "recovery_ms": 45000
}
```

- `source` 为非空字符串，精确匹配来源；`metric` 为精确指标名或含 `*` 的通配；`labels` 为标签等值条件（可省略），需全部命中。`pending_ms`（持续时长）、`suppression_ms`（抑制时长）、`recovery_ms`（恢复时长）均为非负整数，单位毫秒，沿用项目现有时间口径。
- 判定以事件时间和规则维度为准。同一规则对同一 `来源 + 规范 labels` 组合的连续匹配自首次命中起累计，跨度达到 `pending_ms` 时立即进入 `suppressed`，抑制结束时间为触发时刻加 `suppression_ms`；抑制窗口不因重复样本延长。抑制时长结束后进入恢复观察：恢复期内再次命中只重新开始观察（记录中的抑制结束时间不变），只有安静度过完整 `recovery_ms` 才回到未命中。不同标签组合互不影响。
- 规则命中时不删除原始观测：样本与归并结果沿既有路径流动，原本应发出的告警被标记为 `suppressed`（与既有抑制判定取并集，`suppressed_alert_ids` 随之更新）。同一事件同时命中多条规则时，每条规则各自保留一条状态（按 `rule_id` 升序），告警的汇总抑制结果以最早结束的抑制窗口为准。
- 重复提交同一事件与同一规则不会产生重复窗口或相互矛盾的状态（每个 `rule_id + source + labels` 组合至多一条状态记录）。

查询结果每条包含 `rule_id`、`source`、`labels`、`active_start_ms`（活跃开始时间）、`suppression_end_ms`（抑制结束时间，尚未进入抑制时为 `null`）与 `status`：`missed`（未命中）、`pending`（观察中）、`suppressed`（抑制中）、`recovered`（已恢复，即恢复观察期）。

```python
from metric_fusion import (
    WindowSuppressionEngine, process,
    query_window_suppressions, reset_window_suppressions,
)

result = process({..., "window_suppression_rules": [...]})
result["suppression_states"]          # 本次启用时响应新增该字段
query_window_suppressions(rule_id="cpu-flap", now_ms=60000)
```

- `process(..., window_engine=)` 可传入自定义 `WindowSuppressionEngine` 以隔离状态；默认使用进程级引擎，因此跨调用的历史状态仍可查询。`MetricBatchService(window_suppression_rules=[...])`、`service.set_window_suppression_rules(rules)`（整体替换，校验全有或全无）、`service.query_suppression_states(rule_id=, source=, labels=, now_ms=)` 提供同样的能力；批次请求也可携带 `window_suppression_rules` 在该批事件记录前生效。`service.reset()` 清空已记录状态但保留规则配置；批次撤回不改写抑制历史。
- 查询的 `now_ms` 缺省取引擎已见的最大事件时间；状态判定始终基于事件时间而非墙钟。
- 修改 `pending_ms` / `suppression_ms` / `recovery_ms` 不追溯已经记录的命中；删除规则仅停止后续匹配，历史抑制状态仍可按 `rule_id` 查询。
- 错误：时间戳缺失、持续时长为负、抑制时长或恢复时长为负、来源为空、指标名匹配条件为空、标签匹配条件非法（含 `rule_id` 为空或重复）统一抛 `RuleConfigurationError`；处理事件遇到无法排序的时间戳（非数值、非有限或为负）抛 `EventTimestampError`。两者均为 `ValueError` 子类；校验失败为整批拒绝，不产生部分效果。HTTP 下分别返回 400，`code` 为 `rule_configuration_error` / `event_timestamp_error`。
- HTTP：`PUT`/`POST /v1/window_suppression_rules`（请求体为规则列表或 `{"rules": [...]}`，整体替换配置）；`GET /v1/window_suppressions?rule_id=&source=&now_ms=` 返回 `{"suppression_states": [...]}`。

## 计划维护窗口（可选）

在请求中加入 `maintenance_windows`（窗口数组）即启用计划维护期间的告警抑制；缺省不提供时，输出、抑制结果与异常行为与上述基线完全一致，且不会读取或校验该配置。

窗口形如：

```json
{
  "window_id": "db-patching",
  "start_ms": 1700000000000,
  "end_ms": 1700003600000,
  "source": "agent-a",
  "name": "cpu.usage",
  "labels": {"host": "db-1"}
}
```

- `window_id` 为非空字符串，同一批配置内不得重复；`start_ms` / `end_ms` 为非负有限数值且 `end_ms > start_ms`，区间为左闭右开 `[start_ms, end_ms)`。
- `source`、`name`、`labels` 为匹配条件：`source` / `name` 提供时为非空字符串并精确匹配告警同名字段；`labels` 为键非空的映射，作为子集条件全部命中告警 `labels`。三者均可省略，但至少提供一个；所有提供的条件必须同时命中。
- 判定只看告警的 `timestamp_ms`：命中任一窗口的告警进入抑制结果，与既有 `suppression_ms` 抑制及时间窗抑制取并集，`suppressed_alert_ids` 不重复；告警字段与顺序不变，解释模式下沿用现有 `status` 表达（`suppressed`），不产生解释记录。
- `process` 请求可直接携带 `maintenance_windows`；`MetricBatchService(maintenance_windows=[...])` 构造时接收配置，`service.set_maintenance_windows(windows)` 全量替换（`None` 清空），`service.reset()` 清空数据但保留配置。批次迟到修正或撤回后重新查询时按当前告警集重新判定。
- series、聚合（`aggregations`）、来源法定人数（`source_quorum`）与查询过滤不读取维护窗口；批次应用/撤回请求不携带该配置。
- 校验：配置或字段非法时，库调用与无状态处理抛 `ValueError("invalid maintenance_window")`；CLI 输出该消息并以 2 退出；HTTP 返回 400，`{"code": "invalid_maintenance_window", "message": "invalid maintenance_window"}`。校验为整批全有或全无，失败时已有配置保持不变，无部分效果。
- HTTP：`PUT`/`POST /v1/maintenance_windows`，请求体为窗口数组或 `{"maintenance_windows": [...]}`，整批校验通过后一次替换，成功返回 `{"status": "ok"}`。

## 抑制审计查询（可选）

`process`、`POST /process` 与 `MetricBatchService` 支持抑制审计：请求中加 `"include_suppression_audit": true`（默认 `false`）时，响应新增 `suppression_audit`；缺省或为 `false` 时输出与基线完全一致。该参数只接受布尔值，`"true"`、`1`、`null` 等其他值一律由 `process` 抛 `ValueError("invalid suppression audit")`，`POST /process` 返回 400 及 `{"code": "invalid_request", "message": "invalid suppression audit"}`，CLI 输出该消息并以退出码 2 结束。该校验与其他选项一样在触碰任何状态前完成，失败不产生部分审计结果，其他既有错误（配置非法、`duplicate alert_id`、事件时间不可排序等）沿用原异常类型与消息。

`suppression_audit` 为数组，**每条已裁决告警恰有一条记录**，顺序与告警裁决顺序一致；记录固定含 `alert_id`、`suppressed`、`causes`，未抑制时 `causes` 为空数组：

```json
{"alert_id": "a2", "suppressed": true, "causes": [
  {"kind": "time", "id": null},
  {"kind": "suppression_rule", "id": "disk-flap"},
  {"kind": "window_rule", "id": "cpu-flap"},
  {"kind": "maintenance", "id": "db-patching"}
]}
```

- `causes` 每项固定含 `kind` 与 `id`；`kind` 只能是 `time`、`suppression_rule`、`window_rule`、`maintenance`。`time` 的 `id` 恒为 `null`；其余三类使用命中的 `rule_id` 或 `window_id`。
- 同一 `kind` 与 `id` 不重复；一条告警可同时被多种原因抑制，多原因全部列出。排序固定为先按上述 `kind` 顺序（time → suppression_rule → window_rule → maintenance），同类内按 `id` 字典序。
- `time` 对应基线 `suppression_ms` 时间抑制的最终判定；`window_rule` 与 `maintenance` 沿用最终抑制判定（窗口规则与维护窗口命中即列出，窗口规则原因与聚合判定一致，按规则 id 排序列出全部仍在抑制区间内的命中规则）。`suppression_rule` 仅在解释模式（`enable_explanations: true`）已启用且确实产生规则抑制时记录；解释模式下基线时间抑制已被规则裁决取代，因此不再产生 `time` 原因。
- 审计不改变告警字段与顺序、`suppressed_alert_ids`、`explanations`、`suppression_states`、`round(value, 6)`、窗口边界、来源过滤、批次幂等与批次秩等既有行为。

有状态服务：

```python
service = MetricBatchService(downsample_ms=60000, suppression_ms=30000)
audit = service.query_suppression_audit()   # 返回 suppression_audit 数组本身
```

- `query_suppression_audit()` 每次按当前已存告警、窗口状态、维护窗口与抑制规则重新裁决：批次补丁、迟到修正与撤回后反映最新裁决（例如撤回抑制者批次后，原被抑制告警记录变为 `suppressed: false`、`causes: []`；撤回告警所在批次后其记录消失）。
- 幂等：重复应用同一批次（无操作成功）或重复撤回同一 `batch_id` 都不增加记录；撤回后以同一 `batch_id` 重新提交修正内容时按新裁决生成记录。
- 查询只读：不改变 `GET /v1/alerts`、`GET /v1/series` 的结果或任何配置状态。

HTTP：新增 `GET /v1/suppression_audit`，返回 `{"suppression_audit": [...]}`；无参数，查询不改变 `GET /v1/alerts`、`GET /v1/series` 或配置状态。

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
- `POST /process`：旧版无状态入口（支持 `include_suppression_audit`）。`POST /v1/query`：按 `name/labels/start_ms/end_ms` 查询 series。`GET /v1/series`、`GET /v1/alerts`：全量查询；`GET /v1/suppression_audit`：返回 `{"suppression_audit": [...]}`，只读且不改变其他查询与配置。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
