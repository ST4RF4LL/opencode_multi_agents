---
name: extract-acp-quadruples
description: Infer evidence-backed intended database access policies as exact D/O/R/AC quadruples in an independent bounded policy session for the platform BAC analysis workflow.
---

# 预期数据库权限策略

只在 Orchestrator 分派的 `mode=acp` 中处理给定资源组，使用 `P03_PLAN.security-threat-modeler.acp` 契约。读取 `.opencode/lib/bac/workflow.md`、[模型](references/acp-model.md)，Java 项目再读 [Java 证据](references/java-evidence.md)。复用既有冻结清单，不重建函数全集、不修改被审计源码、不创建嵌套任务。

输出策略分片和资源角色规范映射。策略代表应有控制，不能只抄某条实际路径的控制，也不能由所有路径都缺检查推导 NONE。证据优先级为明确策略/有效配置、已核实的框架角色语义、同 D/O/R 的独立一致实现、归属关系及其强制约束；名称注释只能提供线索。不得消费下游 BAC 候选、缺失标记或复核结论再调整策略。

将表、实体、Mapper/SQL 别名统一到含数据库命名空间的 D；CRUD 多操作拆分。保留应用角色原名，只在有证据时将权限码映射到角色。四元组恰好 `{D,O,R,AC}`，角色未知进入 unresolved。相同 D/O/R 有不同可信 AC 时进入 ACP_CONFLICT；没有足够证据不生成高置信度最终策略。

tenant、部门、共享、委托、状态、字段与非数据库对象进入 out_of_model 并说明原审计应继续检查，不能都归为直接 owner HAC。明确公开读可以为 NONE，owner 外键本身不证明所有操作需要 HAC。

分片使用平台请求内 `acp` 的结构：repository.root/scope_digest/revision、producer（本次真实独立 session）、coverage、quadruples、unresolved、out_of_model、limitations。每条证据使用中文 claim 和冻结源码 locator，详见 shared detect-bac-risks 的 references/input-contract.md。规范目录为 resources/roles/aliases/known_gaps，每项规范名映射都有证据。

输出到注入 reports 根目录的 `bac/<audit_id>/policies/`，按资源组保存不可变分片。同范围已有有效策略可复用；冲突不按写入顺序覆盖。预算或证据不足时保留具体资源/角色缺口，不等待 Owner 回答，不声称完整提取。
