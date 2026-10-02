# Metric Fusion

可观测性指标汇聚服务：多源指标归并、降采样与告警抑制。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。

## 状态

已实现指标归并、降采样与告警抑制，无第三方依赖，Python 3.11+。

## 用法

```python
from metric_fusion import process
result = process(request)  # request/result 均为 dict，UTF-8 JSON
```

命令行：

```bash
python -m metric_fusion request.json > result.json
```

成功退出码 0；失败时异常信息写入标准错误并以退出码 2 结束。

## 行为

- 指标按 `name + 规范 labels`（labels 键排序）归为序列；同 `(source, name, labels, timestamp_ms)` 去重，后出现的覆盖先出现的。
- 桶起点为 `timestamp_ms // downsample_ms * downsample_ms`；同桶跨 source 取均值，收集去重来源，输出桶起点、均值、样本数、来源；数值 `round(value, 6)`。
- 序列按 name、规范 labels、timestamp_ms 排序。
- 告警按 `rule + name + 规范 labels` 分组，按 `timestamp_ms, alert_id` 排序：首条发出；距最近发出不超过 `suppression_ms` 且级别不更高者抑制；更高级别立即发出并重置抑制起点。
- 校验失败抛出对应消息的 `ValueError`：`invalid request` / `invalid metric` / `invalid value` / `invalid alert` / `invalid severity` / `duplicate alert_id` / `invalid downsample_ms` / `invalid suppression_ms`；命令行解析失败为 `invalid JSON`。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
