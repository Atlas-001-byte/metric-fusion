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

`process`、`POST /v1/query` 与 `MetricBatchService.query_series` 接受可选的 `aggregations` 映射：键为精确指标名，值只能是 `avg`、`min`、`max`、`sum`、`last`。未命中映射的指标仍用 `avg`，未提供 `aggregations` 时行为与基线完全一致。

- 去重（`source/name/labels/timestamp_ms` 后覆盖先）与窗口起点（`timestamp_ms // downsample_ms * downsample_ms`）不变；同 `name` + 规范 labels 的窗口内：`avg/min/max/sum` 分别取平均、最小、最大、总和；`last` 取 `timestamp_ms` 最大的样本，时间相同取 `source` 字典序最大者。
- 输出字段不变（`name/labels/timestamp_ms/value/count/sources`，不增加聚合类型字段），`count` 仍是去重样本数，`sources` 去重排序，`value` 仍 `round(value, 6)` 且 `-0.0` 统一为 `0`；排序不变。
- 有状态服务在补丁、迟到修正与批次撤回后按当前胜者样本重算所选函数；批次秩、幂等、`affected_streams`、`recomputed_windows`、告警重裁与顺序无关语义不变。聚合只影响选定的 series 查询：`GET /v1/series`、`GET /v1/alerts` 与告警抑制不读取该配置。
- 校验：`aggregations` 不是字符串到允许函数名的映射、键为空串或值不支持时，库调用抛 `ValueError("invalid aggregation")`；HTTP 返回 400，`{"code": "invalid_request", "message": "invalid aggregation"}`；CLI 输出该消息并以 2 退出。校验失败不部分修改状态。

## 来源法定人数过滤（可选）

`process`、`POST /v1/query` 与 `MetricBatchService.query_series` 接受可选的 `source_quorum` 映射：键为精确指标名，值为正整数阈值。去重、窗口归并与来源收集完成后，按 `name + 规范 labels + 窗口` 判断：只有窗口的**去重 sources 数量大于或等于阈值**时才输出该行。未达到阈值的窗口不进入 series，不做补点、部分输出或错误处理。未提供 `source_quorum`、或窗口指标名未命中映射时，维持现有默认聚合（`avg`）与全部窗口输出。

- 阈值按窗口的完整去重来源集判断（与 `sources` 字段同一集合），不能按样本数（`count`）或请求条数判断；`source/name/labels/timestamp_ms` 去重先于覆盖度判断。
- 可与 `aggregations` 同时使用：达到阈值的窗口仍按所选函数输出 `round(value, 6)`、`-0.0` 归一、`count`、`sources` 与既有排序；未达到阈值的窗口即使配置了聚合函数也不输出。
- 有状态服务在补丁、迟到修正或批次撤回后重新查询时，按当前胜者样本重算来源覆盖，只输出仍满足阈值的窗口；批次秩、幂等与撤回结果不受影响。
- 查询范围、`name` 与 `labels` 过滤及排序继续沿用当前口径。`GET /v1/series`、`GET /v1/alerts` 与告警抑制（含抑制解释、时间窗规则）不读取 `source_quorum`；批次应用/撤回请求也不接受该配置，其行为与响应字段不变。
- 校验：`source_quorum` 必须是字符串到正整数的映射，键非空，值不能为布尔值、零、负数或浮点数；非法时库调用抛 `ValueError("invalid source_quorum")`，HTTP `POST /v1/query` 返回 400，`{"code": "invalid_request", "message": "invalid source_quorum"}`，CLI 输出 `invalid source_quorum` 并以 2 退出。校验失败不改变已有状态。

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

## 计划维护窗口告警抑制（可选）

在请求中加入 `maintenance_windows`（窗口数组）即启用；缺省不提供时，所有输出与基线完全一致，不读取也不校验该字段。维护窗口是纯时间判定：**只看告警的 `timestamp_ms`**，不消费指标样本，也不参与 series、聚合、来源法定人数与查询过滤。

窗口形如：

```json
{
  "window_id": "deploy-db-1",
  "start_ms": 100000,
  "end_ms": 200000,
  "source": "agent-a",
  "name": "cpu.usage",
  "labels": {"host": "db-1"}
}
```

- `window_id` 为非空字符串且同批内不重复；`start_ms`/`end_ms` 为非负有限数值（整数或浮点，布尔值拒绝），且 `end_ms > start_ms`。区间左闭右开：`start_ms <= timestamp_ms < end_ms`，恰在 `end_ms` 的告警不被抑制。
- 匹配条件为精确匹配：`source`、`name` 提供时为非空字符串；`labels` 是键非空的映射，按标签子集精确等值命中（值可为任意 JSON 值，按类型严格相等）。三者都可省略，但至少提供一个。
- 命中窗口的告警标记为抑制，与既有 `suppression_ms` 时间抑制（含更高级别突破）及时间窗规则抑制**取并集**：`suppressed_alert_ids` 不重复且保持告警原顺序；非解释模式下告警输出字段仍为 `alert_id/severity/suppressed`。
- 解释模式（`enable_explanations`）下沿用现有抑制状态表达：被维护窗口命中的告警 `status` 为 `suppressed"`，其余字段、顺序与 `explanations` 记录不变（维护窗口自身不产生解释记录）。
- 无状态 `process` 请求可直接携带 `maintenance_windows`，仅对当次裁决生效。

有状态服务：

```python
service = MetricBatchService(maintenance_windows=[...])
service.set_maintenance_windows([...])   # 全量替换；校验整批通过后才生效
service.reset()                          # 清空数据，但保留维护窗口配置
```

- 批次迟到修正或撤回后再次查询时，按当前告警集对当前配置重新判定。
- 批次应用请求不读取该配置字段；series、聚合、来源法定人数、`POST /v1/query` 过滤均不读取维护窗口。
- HTTP：`PUT` 或 `POST /v1/maintenance_windows` 更新配置，请求体为窗口数组或 `{"maintenance_windows": [...]}`，整批校验通过后一次替换，成功返回 `{"status": "ok"}`。
- 校验：`window_id` 为空/非字符串/重复，时间戳非数值、非有限、为负或 `end_ms <= start_ms`，三个条件全部缺失，`source`/`name` 非法或 `labels` 不是键非空的映射时，库调用与无状态处理抛 `ValueError("invalid maintenance_window")`（公开异常类型 `MaintenanceWindowError`，为 `ValueError` 子类）；CLI 输出该消息并以 2 退出；HTTP 返回 400，`{"code": "invalid_maintenance_window", "message": "invalid maintenance_window"}`。任何失败均整批拒绝，已有配置保持不变、无部分效果。

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
- `PUT`/`POST /v1/maintenance_windows`：整体替换维护窗口配置（请求体为数组或 `{"maintenance_windows": [...]}`）；非法时 400，`code` 固定为 `invalid_maintenance_window`，已有配置不变。
- `POST /process`：旧版无状态入口。`POST /v1/query`：按 `name/labels/start_ms/end_ms` 查询 series。`GET /v1/series`、`GET /v1/alerts`：全量查询。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
