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

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
