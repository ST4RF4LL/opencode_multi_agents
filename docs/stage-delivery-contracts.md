# 八环节固定交付件设计

## 1. 结论

工作台八个环节使用独立的“阶段交付清单”作为环节完成的唯一聚合证明，但不替换
现有 P00-P10 Stage/Agent 信封。两层职责如下：

- P00-P10 信封证明某次 Agent 调用收到了什么、返回了什么、摘要是否绑定。
- 八环节清单证明一个面向操作员的工作台环节，是否收齐业务制品、通过内容校验、
  满足前置条件并拥有可恢复锚点。

规范注册表位于
`.opencode/skills/common-subagent/audit-artifact-management/contracts/workbench-stage-deliveries.json`。
每个实际清单写入：

```text
reports/stage-deliveries/<audit_id>/<stage_id>.r<round>.json
```

当前注册表状态是 `ACTIVE`，执行模式是 `ENFORCED`。新建工作台任务只有在八个环节
的物化清单、文件 SHA-256、前驱绑定和验证证据全部通过后才能进入 `completed`。
OpenCode 正常退出但交付不完整时，任务会标记为可恢复的 `interrupted`；历史无清单
任务继续以“历史制品推断”只读展示，不被伪装成清单完成。

## 2. 八环节映射

| 工作台环节 | 内部阶段 | 固定核心输出 | 完成门禁 |
| --- | --- | --- | --- |
| 范围冻结 | P00 + P01 | scope manifest、parser capabilities | P00/P01 信封有效、范围已冻结、零 gap |
| 资产侦察 | P01 | 函数集合、接口、抽取覆盖、威胁路由、侦察摘要、资产集合 | P01 信封完整、接口抽取门禁通过 |
| 威胁建模 | P02 + P03 | threat model、Focus Areas、输入快照、Coverage Plan、Ledger | 威胁模型内容契约与计划信封通过 |
| 多维漏洞审计 | P04 + P07 | Focus audit result 集合、Finding 集合、可选 SARIF 集合 | 所有 assignment × lens/discovery 完成，报告 reconcile，Finding v2 有效 |
| 证据关联 | P05 + P06 + P07 | 初步攻击链、关联报告、follow-up 集合、结构覆盖 | 关联信封和结构 intake 通过；有阻断 gap 时不得完成 |
| 发现裁决 | P08 | 裁决输入/输出、完整动态验证请求集合（可为零项） | 候选守恒、初步语义裁决完整、请求集合显式交付 |
| 验证复核 | P08 | truth intake、quick result、正方/反方/Moderator、routing、CVSS、终态攻击链、三类覆盖门禁 | 快速动态全任务最多 120 秒；未确认项三方静态复核；只有 routing `TRUE_POSITIVE` 可进入 CVSS/攻击链 |
| 报告封存 | P08 + 可选 P10 | 报告模型、中文 Markdown、可选优化摘要 | 模型绑定 routing/CVSS/攻击链，确定性报告逐字节验证，八环节物化验证通过 |

工作台未单列 Coverage Plan，因此“威胁建模”聚合 P02 与 P03。初步攻击链属于证据
关联，初步 finding 裁决属于发现裁决；真实性 routing、终态 CVSS 与攻击链都属于
验证复核。人工完整动态验证是报告主链之外的 sidecar，不属于八环节完成条件。

## 3. 通用阶段交付清单

所有环节共享同一个固定结构：

```json
{
  "schema_version": 1,
  "registry_id": "workbench-stage-deliveries-v1",
  "registry_digest": "<registry sha256>",
  "template_id": "WB04_MULTI_DIMENSION_AUDIT",
  "stage_id": "audit",
  "stage_order": 4,
  "audit_id": "audit-id",
  "round": 1,
  "status": "COMPLETE",
  "scope_binding": { "state": "FROZEN", "scope_digest": "<sha256>" },
  "activated_conditions": [],
  "predecessor_manifests": [],
  "input_artifacts": [],
  "output_artifacts": [],
  "validation_results": [],
  "gaps": [],
  "producer": {
    "agent_name": "security-audit-orchestrator",
    "agent_session_id": "session-id",
    "internal_stage_ids": ["P04_FOCUS_EXECUTION"],
    "stage_agent_contract_ids": ["P04_FOCUS_EXECUTION.web-source-auditor"]
  },
  "started_at": "2026-08-12T00:00:00.000Z",
  "completed_at": "2026-08-12T01:00:00.000Z",
  "completion": {
    "required_outputs_satisfied": true,
    "required_validators_passed": true,
    "predecessors_complete": true,
    "complete": true
  },
  "manifest_digest": "<sha256>"
}
```

`COMPLETE` 的含义固定为：

1. 所有 required 以及已激活 conditional 输出均存在，并符合 cardinality。
2. 所有 required 以及已激活 conditional validator 结果均为 `PASS`。
3. 所有正向前置环节清单均为 `COMPLETE`；回边来源满足回边声明的允许状态。
4. scope 已冻结。
5. `gaps=[]`。
6. 清单摘要有效。

`PARTIAL`、`BLOCKED`、`FAILED` 和 `NOT_APPLICABLE` 必须保留结构化 gap，不得通过
自然语言或文件存在性解释成完成。

## 4. 集合交付件

多会话或零到多对象使用统一 `artifact-set-index-v1`，例如：

- `function-manifest-set`
- `recon-inventory-set`
- `focus-audit-result-set`
- `finding-artifact-set`
- `sarif-set`
- `follow-up-packet-set`
- `external-runtime-validation-request-set`
- `external-runtime-validation-result-set`

集合索引必须记录每个成员的 artifact type、路径、SHA-256、media type 和可选 JSON
Pointer。集合没有成员时仍须写 `item_count=0` 的合法清单。这样可以严格区分：

- 已执行但没有发现漏洞；
- 没有请求动态验证；
- Agent 或编排器漏交付。

集合写入后运行 `seal-artifact-set-index.mjs` 计算确定性 `set_digest`；八环节物化校验会
重新计算该摘要，并逐项校验成员文件是受控 `reports/` 下的普通文件且 SHA-256 一致。

## 5. 轮次与回退

正常主链保持单向：

```text
scope → recon → threat → audit → correlation → adjudication → validation → report
```

唯一固定回边是：

```text
correlation --correlation_gap_round--> audit (round + 1)
```

当关联报告仍有阻断矛盾、coverage gap 或 follow-up packet 时，correlation 清单保持
`PARTIAL`，并用 `correlation_gap_round` 启动下一轮定向审计。该回边只接受来源状态
`PARTIAL`；新轮次不得覆盖旧清单。
后续裁决只能消费最后一个完整关联轮次。

## 6. 动态验证边界

动态验证请求集合始终由发现裁决显式输出，包括零项集合。验证分成两条严格分离的
路径：

1. 创建任务时未 ENABLE 测试环境：quick result 对每项写 `SKIPPED`，所有初步支持项
   进入本地正方、反方、Moderator 静态复核。
2. 创建任务时已 ENABLE 且私有上下文摘要有效：所有初步支持项进入同一个 loopback
   快速批次，全任务硬上限 120 秒；runtime request 是可选结构化提示而非准入条件，
   只有 `CONFIRMED` 可跳过三方静态复核。CONFIRMED 引用的脱敏证据文件由
   controller 逐文件计算 SHA-256 并写入 quick result，物化校验会再次核对。
3. 完整动态验证始终为 `MANUAL_ONLY`。它只在用户到验证页逐次点击、再次提供授权
   loopback 环境与专用账号后运行，结果是 sidecar，不自动改写 routing 或终稿。

快速动态无法确认、超时或受阻都不是主链失败，而是显式转入静态三方；三方或 routing
制品缺失、摘要漂移、finding accounting 不完整才会阻断验证环节。

## 7. 断点恢复

每个模板都定义 `anchor_artifact_types` 和恢复规则。恢复时先校验已落盘清单及锚点：

- 上游摘要没有变化：保留已校验输出，只补缺失或失败项。
- 上游摘要变化且 `invalidate_on_input_change=true`：本环节失效并重建。
- 多 Agent 审计：按输出信封、Ledger receipt 和集合索引恢复，不重跑已完成 session。
- truth-validation 角色制品摘要未变：复用已完成角色，从最早缺失角色继续。
- 报告模型或 Markdown 已生成但报告环节未封存：重新校验输入摘要并确定性渲染，禁止手改。

## 8. 已完成接入与兼容边界

- `seal-stage-delivery.mjs` 从请求生成摘要绑定的阶段清单，并拒绝静默覆盖不同的完整轮次。
- `verify-stage-deliveries.mjs` 递归验证八个环节、前驱清单、输入来源、普通文件与 SHA-256。
- 工作台进度优先来自物化清单；新任务强制执行，旧任务保留带标签的历史推断。
- Runner 退出码为 0 但不足八环节时会进入可断点恢复的 `stage-delivery-incomplete`。
- 当前部分聚合制品仍由 Stage/Agent 信封、成员文件摘要及下游内容校验共同约束；注册表
  的 `ENVELOPE_ONLY` 表示校验组合方式，不表示该环节处于影子模式。

## 9. 校验

注册表与清单使用：

```sh
node .opencode/skills/common-subagent/audit-artifact-management/scripts/validate-stage-delivery.mjs \
  --registry-only

node .opencode/skills/common-subagent/audit-artifact-management/scripts/validate-stage-delivery.mjs \
  --manifest reports/stage-deliveries/<audit_id>/<stage_id>.r<round>.json

node .opencode/skills/common-subagent/audit-artifact-management/scripts/seal-stage-delivery.mjs \
  --request tmp/<audit_id>/stage-delivery-request.json

node .opencode/skills/common-subagent/audit-artifact-management/scripts/verify-stage-deliveries.mjs \
  --audit-id <audit_id> --reports-root reports
```

回归测试：

```sh
npm --prefix .opencode run test:stage-delivery-contract
```
