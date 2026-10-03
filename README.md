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

## 可解释抑制（explain 模式）

默认关闭。请求中 `"explain": true` 时启用，此时抑制由 `suppression_rules` 驱动（不再使用 `suppression_ms` 做判定，但该字段仍按原规则校验）；关闭时 `suppression_rules` 被忽略，归并、降采样、抑制判定与异常行为与基线完全一致。

规则字段：

- `rule_id`：非空字符串，全局唯一（重复报 `duplicate rule_id`）。
- `metric` / `metric_prefix`：指标选择器，精确名或前缀，至多出现一个；都不给则匹配全部指标。
- `labels`：标签选择器，字符串键值对；告警的 labels 包含全部条件才算命中。
- `min_severity`：可选，`info`/`warning`/`critical`，默认 `info`；只覆盖不低于该级别的告警。
- `duration_ms`：非负整数，抑制时长。

处理与判定：

- 批次内先按 （指标名， 规范标签集， timestamp_ms, alert_id) 整理告警，再逐条处理。
- 每条告警选择匹配规则：标签条件更多者优先，其次指标选择更精确者（精确名 > 更长前缀 > 无），完全并列取 `rule_id` 字典序最小者。
- 每条规则维护最近一条有效（active）告警作为抑制者；落在 `[抑制者时间, 抑制者时间 + duration_ms]` 窗口内的匹配事件标记 `suppressed`，否则为 `active` 并成为新的抑制者。无匹配规则的告警一律 active。
- 告警输出字段与顺序不变；结果新增 `explanations` 列表，每条记录含 `suppressed_fingerprint`、`suppressor_fingerprint`、`rule_id`、`started_at`（被抑制事件的触发时间）、`expires_at`（抑制者时间 + duration_ms）。
- 指纹：`alert_fingerprint(name, labels)`，即 `{"name":…,"labels":…}` 规范 JSON 的 SHA-256 十六进制。

查询：

```python
from metric_fusion import ExplanationStore, process

store = ExplanationStore()
process(request, explanation_store=store)          # explain 开启时记录入库
store.query(fingerprint=fp, now_ms=now)            # 按被抑制告警指纹过滤
store.query(rule_id="r1", now_ms=now)              # 按规则编号过滤
store.query(suppressor_fingerprint=fp, now_ms=now) # 按抑制者指纹过滤
```

- 不存在的指纹或 `rule_id` 返回空列表，不抛异常；参数类型错误或 `now_ms` 非有限非负数值抛 `ValueError`。
- `now_ms >= expires_at` 的记录带 `ended_at`（等于已知的 `expires_at`，非猜测）；尚未结束的记录不含 `ended_at`；不传 `now_ms` 则一律不带。

校验：规则缺字段、类型错误、非法选择器（如 `metric` 与 `metric_prefix` 并存）、未知 `min_severity`、负数或非整数 `duration_ms`、重复 `rule_id`、`explain` 非布尔等统一抛 `ValueError`（新增消息：`invalid explain`、`invalid suppression_rules`、`invalid suppression rule`、`duplicate rule_id`、`invalid selector`、`invalid duration_ms`）。任何校验失败时本次处理不产生部分输出，也不写入 explanation store。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
