---
name: java-resource-exhaustion
description: "Detect Java resource exhaustion where attacker-controlled numeric parameters reach memory allocation, collection capacity, pagination, batches, fan-out, recursion, worker pools, queues, or expensive reads without effective lower and upper bounds. Use for Java CWE-400/CWE-770/CWE-789 review of size, limit, count, pageSize, capacity, repeat, depth, workers, parallelism, and timeout parameters."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D9
  weakness: resource-exhaustion
---

# Java Resource Exhaustion

## 目标

识别外部可控数值进入高成本资源 sink 且没有有效边界的可达路径。重点不是“参数缺少 `@Min`/`@Max`”，而是证明攻击者可以让 Java 服务产生不合理的内存、CPU、线程、队列、数据库、递归或下游请求消耗。

## 审计流程

1. 定位 HTTP path/query/body、消息、导入文件和持久化任务中的 `size`、`limit`、`count`、`pageSize`、`capacity`、`repeat`、`depth`、`workers`、`parallelism`、`timeout` 等数值。
2. 追踪到高成本 sink：数组/`ByteBuffer`/集合预分配、`String.repeat`、分页与查询 limit、批循环、流 range、递归深度、任务 fan-out、线程池/队列容量、大块读取或解压。
3. 计算实际放大关系，包括乘法、位移、单位转换、嵌套循环和“单项成本 × 数量”；检查整数溢出、负数绕过和截断。
4. 验证控制是否在 sink 前实际执行：Bean Validation 是否启用、手工 range/clamp 是否覆盖所有入口、默认值是否有界、网关限制是否适用于当前路由。
5. 同时检查总量控制：每用户/租户配额、并发限制、速率限制、队列界限、超时、取消、背压和容器内存限制。单请求上限不能替代总量控制。
6. 只在入口可达、数值可控、资源 sink 明确、有效上限缺失且影响可信时输出 Finding；否则输出 Candidate 或 Rejected。

## 控制判定

- `@Min`/`@Max`、`@Positive`、`@Size` 只有在对象或参数经过实际 Bean Validation 时才有效。
- 只设最小值不能阻止极大正数；只设最大值可能留下负数、溢出或特殊值路径。
- `Math.min(value, MAX)` 需确认后续没有在 clamp 前分配，也没有溢出后再次放大。
- JVM/container memory limit 只能限制故障范围，通常不能证明接口免受拒绝服务。
- 数据库、线程池或下游服务自身的限制不能自动替代应用层按主体的公平使用控制。

## 停止与降噪条件

- 数值完全来自受信配置或编译期常量，外部输入不参与。
- sink 前存在可证明生效的上下界、溢出安全运算和与成本匹配的总量控制。
- 命中只是字段名、DTO、验证注解缺失或昂贵 API，本身没有 source-to-sink 数据流。
- 影响仅是一次有界失败且没有服务可用性或共享资源影响证据。

## 输出要求

每个 Finding 用中文回答：参数从哪里进入、经过哪些变换、到达哪个资源 sink、最大成本为何不受控、现有控制为何无效、攻击者需要什么权限、影响是单请求内存耗尽还是 CPU/线程/队列/数据库/下游放大。严重度结合可认证性、重复成本、共享影响和恢复方式判断，不因“理论上可输入 `Integer.MAX_VALUE`”自动定高危。

候选定位规则位于 `rules/semgrep/java-resource-exhaustion-patterns.yaml`。这些规则只用于发现需要继续追踪的数据点。

## OpenCode 集成

- Owner agent: `java-source-auditor`，collection: `java-subagent`。
- Catalog item: `JAVA-RESILIENCE-01`，dimension: D9。
- 与 `java-idor` 交叉检查批量对象操作的逐项授权，与 `java-ssrf` 交叉检查 URL 列表导致的出站 fan-out。
