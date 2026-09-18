# 漏洞交付内容格式 v1

用途：完整记录审计证据及验证过程，让审阅者能够重建判断，随后支持修复。以下字段放在原始 Finding v2 的 `report_details` 中，受同一个 Finding 对象摘要保护。契约版本为 `finding-details.v1`，不是新的漏洞真实性状态。

| 字段 | 必须回答的问题 | 校验要求 |
|---|---|---|
| `root_cause` | 为什么存在漏洞？应有行为和实际行为分别是什么？ | `summary`、`expected_behavior`、`actual_behavior` 均为中文非空说明 |
| `code_context` | 具体哪段代码支持上述主张？ | `RECORDED` 时至少一个片段，每段绑定原始事实索引；`UNAVAILABLE` 时片段为空且必须说明原因 |
| `path` | 可控输入如何经过业务调用、防护判断，最终造成安全影响？ | 至少两步，逐步提供 `description` 和有效 `evidence_fact_indexes` |
| `reproduction` | 如何在授权隔离环境复核？安全行为和漏洞行为如何区分？ | 环境要求、前提、步骤、两种预期结果；`execution_status` 固定为 `NOT_RUN` |
| `remediation` | 在哪里改、怎么改、为何能消除成因？ | 至少一个具体 `location/action/rationale`，附临时缓解和兼容性说明数组 |
| `regression_tests` | 修复后如何验证攻击被阻断且正常功能仍可用？ | 至少一个 `SECURITY` 和一个 `FUNCTIONAL` 场景，均有明确通过标准 |

`code_context.snippets` 每项为 `evidence_fact_index`、`language`、`text`、`redacted`。引用的路径、行号、源码摘要来自对应 `evidence.facts[index].locator`。仅引用实际检查过的代码，不生成“可能存在”的代码；凭据和个人数据使用占位符并标记脱敏。格式校验只证明片段有来源定位，不替代回源核验。

`reproduction` 只保存设计。运行记录单独存于控制器证据包，包含实际执行状态、观察、证据绑定、结果与清理。任何 Agent 不得因为报告需要复现步骤而启动动态测试；没有有效环境时，动态保持 SKIPPED，设计保持 NOT_RUN。

机器检查入口为 `finding-report-details.mjs`，Finding 解析和工作包验收复用同一实现。工作包声明新契约时缺少此块会拒绝 DONE；旧工作包不追溯强制补写，重新生成详细报告时显示缺口。模板示例见仓库的 `docs/audit-deliverable-format-redesign.md`。
