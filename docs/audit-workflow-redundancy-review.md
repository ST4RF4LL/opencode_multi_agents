# 审计整体流程冗余分析

分析对象是当前 dev 工作区，包括本次快速动态的共享环境改动。依据为 Agent 指令、调度实现、制品契约及确定性脚本的静态阅读；未运行实际审计或采集模型耗时，因此下面不提供虚构的耗时/Token 节省百分比。

## 当前主流程

仓库登记/源码冻结 → Recon 与解析清单 → 威胁模型/Focus 划分 → Coverage Plan → 本地 TODO 工作包 → 语言/平台/AI 审计 → 初步系统攻击链 → 证据关联/有限补充轮次 → 初步语义裁决 → 快速动态（共享准备240秒、逐报告180秒）→ 非确认项静态三方 → 终局 routing → CVSS/终态攻击链 → 覆盖校验与确定性中文报告。

完整动态验证是人工触发的独立 sidecar。winappCli 当前仍为受控 PoC，Windows 客户端与 Java 服务端联合验证是后续设计；不能将这些设计步骤当作当前已运行的重复成本。

## 发现的冗余与冲突

| 优先级 | 环节 | 具体证据与重复成本 | 建议 |
|---|---|---|---|
| P0 | 新旧完成门禁并存，且说明互相冲突 | 新任务在 `audit-runner.mjs` 中使用 `TODO_ENFORCED`；新任务提示明确禁止等待旧 stage-delivery 门禁。但八阶段注册表仍写 `ACTIVE/ENFORCED`、要求新任务八环节物化；orchestrator 的流程仍要求各阶段 seal。模型可能重复补制品、反复封口，或在任务已经终态后继续补齐。 | 将新任务调度唯一依据收敛到 TODO；八阶段仅作展示与证据投影。旧任务通过明确版本的兼容分支读取，不向新任务注入旧封口要求。保留报告真实性和缺口披露约束。 |
| P0 | 一个工作包三视角与单视角制品契约冲突 | orchestrator 第13步及 Java Agent 工作包说明要求同会话做三个视角；同一 Java Agent 的 Tri-Lens 契约却要求恰好一个 `audit_strategy` 且不得混合。orchestrator 第16步、关联 Agent 也仍按 one-lens 读取。结果可能是同一源码读三遍、重复调用同一专家，或为了满足单报告路径而反复重写。 | 保留一次工作包执行，在内部生成三个独立视角记录/报告，由 handoff 绑定完整列表；统一生产、消费及恢复契约。三视角证据保留，不要求三次重新获取相同代码事实。 |
| P1 | 初步裁决后再次完整正反/Moderator 复核 | adjudicator 已逐候选核实版本、source→sink、guards、安全影响和具体反证；进入静态路径后，Affirmative、Negative、Moderator 又各自重建这些要素。一个已支持且未快速确认的候选，可能经历四轮相近的完整语义审查。 | 先复用不可变的事实包（源码片段、版本、调用链、保护措施与摘要），保持结论独立。后续可将初步裁决缩为结构/语义准入，正方负责证明，反方负责反证，Moderator 聚焦争议；高风险或矛盾案例仍完整重建。不能直接把四个角色删成一次投票。 |
| P1 | 无 AI 迹象的项目仍进行全量 AI 第二覆盖 | orchestrator 第12步明确要求即使 Recon 没发现 AI，也覆盖每个可审查文件/函数；`build-coverage-plan.mjs` 对 `domain === "ai"` 纳入所有需审查文件。再乘三个视角，会为普通 Java/客户端代码追加大量缺少 AI 特有假设的阅读和记录。 | Recon 保留全仓 AI 表面识别和可核验负面证据；深度 AI 审计按组件、调用链与数据依赖路由。保留未知表面为 GAP，并用抽查防漏。此项会改变当前明确的完整覆盖政策，需要同步修改适用性模型，不能私自把全量任务写成 PASS。 |
| P1 | 初步/终态攻击链都要求全系统发现 | orchestrator 第18步要求全 Focus/边界/资产的新发现；第26步 routing 后再调用 hunter，而 hunter 通用说明仍要求 new discovery pass 和全量输入。两次的目的不同，但第二次重新发现全部链会重复读取大部分稳定事实。 | 明确 P05 为发现、P08 为基于终局 finding 的重绑定/复核。复用初步图，仅对被拒绝、重分类、影响变化和新增 finding 所关联的边执行分析，最后仍对全体 Focus/边界/资产做确定性记账。不能直接输出未裁定的初步攻击链。 |
| P1 | 机器覆盖统计又由模型关联，并重复 reconciliation | 专家先生成实体记录并 reconcile，关联 Agent 再输出完整 normalized cube 与无损 file/function/catalog 数组；orchestrator 第24步又要求对每个报告 reconcile。`reconcile-audit-report.mjs` 每次读取报告、scope/catalog 并默认原地改写 JSON。相同实体记录多份重述增加 Token、序列化及摘要漂移风险。 | 实体证据只保留一份权威记录；汇总和视图由机器生成，关联 Agent 重点处理冲突、语义去重与追加调查。reconcile 在密封前执行，之后按输入摘要复用；输入改变才重建，交付边界仍复查摘要。 |
| P2 | 静态扫描 doctor 后 plan 再次探测同一工具链 | Java Agent 要求先 `static-scan doctor` 再 `plan`；`static-scan.mjs` 的 `plan()` 内部又直接调用 `doctor()`，后者会探测 pattern engines、Gitleaks、OSV、Java/Javac、Joern。每工作包按现行指令执行时，这一组工具探测至少重复两次。 | 常规工作包直接消费 plan 内含的 health，或复用任务级能力快照；仅在可执行路径、版本/配置改变或实际运行失败后重新 doctor。实际扫描失败检查仍保留。 |
| P2 | 同一流程政策在多处人工维护 | 本次180/240秒改动需要同时修改 runner、Agent、Skill、manifest、阶段契约、Web 与文档；旧三视角/完成条件冲突也体现同类问题。这首先是维护冗余，进而会让模型在运行时遵从互不一致的政策、补做无效工作。 | 运行预算使用共享常量，Agent/阶段/Web 从同一版本化政策生成可读说明，并校验制品版本。先收敛会影响调度的字段，避免再建设一套复杂的配置框架。历史制品保留对应版本解释。 |

## 证据索引

以下定位均可在仓库中直接查阅，步骤号/函数名优先于易随编辑变化的行号：

- **完成门禁**：[audit-runner](../.opencode/web/dynamic-validation-observatory/audit-runner.mjs) 的入口 prompt、`stage_delivery_enforcement: "TODO_ENFORCED"`、`reconcileManagedCompletion()`；[orchestrator](../.opencode/agents/security-audit-orchestrator.md) 的 Stage/Agent I/O Contract 与第24、27步；[八阶段注册表](../.opencode/skills/common-subagent/audit-artifact-management/contracts/workbench-stage-deliveries.json) 的 `lifecycle`。Runner 已区分旧 `ENFORCED` 分支，因此这里不是断言代码把两种门禁同时跑在每个新任务上，问题主要是新任务指令仍混用旧要求。
- **视角契约**：[orchestrator](../.opencode/agents/security-audit-orchestrator.md) 第13、16步；[Java Agent](../.opencode/agents/java-source-auditor.md) 工作包说明和 Tri-Lens Execution Contract；[AI Agent](../.opencode/agents/ai-security-auditor.md) 的单视角说明；[correlator](../.opencode/agents/security-evidence-correlator.md) 输入 one-lens 校验。
- **多轮语义复核**：[初步 adjudicator](../.opencode/agents/security-finding-adjudicator.md) 的 Required work per candidate；[Affirmative](../.opencode/agents/vulnerability-affirmative.md)、[Negative](../.opencode/agents/vulnerability-negative.md)、[Moderator](../.opencode/agents/vulnerability-moderator.md) 的证据重建要求。
- **AI 全量覆盖**：[orchestrator](../.opencode/agents/security-audit-orchestrator.md) 第12步；[build-coverage-plan](../.opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-coverage-plan.mjs) 的 `domainSourceIds` 与 catalog/interface 分组循环。
- **两次系统链**：[orchestrator](../.opencode/agents/security-audit-orchestrator.md) 第18、26步；[hunter](../.opencode/agents/security-attack-chain-hunter.md) 的 P05/P08 输入与全体 reviewed-ID 要求。
- **覆盖复写**：[correlator](../.opencode/agents/security-evidence-correlator.md) 的 Responsibilities/Output；[reconcile-audit-report](../.opencode/skills/common-subagent/audit-coverage-accounting/scripts/reconcile-audit-report.mjs) 的 `main()`；[orchestrator](../.opencode/agents/security-audit-orchestrator.md) 第16、24步。
- **重复 doctor**：[Java Agent](../.opencode/agents/java-source-auditor.md) 的扫描步骤；[static-scan](../.opencode/scripts/static-scan.mjs) 的 `doctor()`、`plan()`。
- **政策多处维护**：[truth-validation-contract](../.opencode/skills/vulnerability-validator-subagent/vulnerability-validation/scripts/truth-validation-contract.mjs)、[artifact-policy](../.opencode/agent-manifest/artifact-policy.json)、[Web 页面](../.opencode/web/dynamic-validation-observatory/public/index.html)、[runner](../.opencode/web/dynamic-validation-observatory/audit-runner.mjs)、[验证 Skill](../.opencode/skills/vulnerability-validator-subagent/vulnerability-validation/SKILL.md)。

## 不应误删的环节

- 三个视角不是天然冗余：sink 可达性、鉴权控制、配置生效语义回答不同问题。应复用事实获取与调度，不合并掉证据维度。
- 摘要、来源绑定、真实证据文件检查与最终 Markdown 字节验证是信任边界。可以缓存确定性计算，但不能用模型说“已校验”替代检查。
- 一次初步链发现和一次终局链复核有不同目的；减少的是终局无差别重新发现的成本。
- 共享测试环境仍需角色隔离、唯一证明标记和逐报告清理；这些工作不能为了节省180秒而省略。
- 函数清单已有 [function-manifest-cache](../.opencode/skills/common-subagent/audit-coverage-accounting/scripts/function-manifest-cache.mjs) 的摘要/解析器版本复用机制，orchestrator 也禁止 Recon 之外重复运行 builder；不能把“解析器每阶段全量重建”当作已证实的问题。
- 当前 blind/seeded 已按高风险或 unresolved 项按需触发；不能把旧的全 Focus 默认多路展开当作现状。Coverage Plan 也已有 source-set 去重和 interface-group 分组，后续优化应基于这些已有机制。

## 建议实施顺序

先统一 TODO 完成条件与三视角制品协议，避免错误重跑；再去掉重复 doctor、合并确定性覆盖视图；随后复用语义事实包和初步攻击链；最后评估 AI 覆盖适用性政策的调整。每项在 Windows/Linux 原生环境记录 Agent 调用数、重复读取文件数、模型 Token、准备/单报告耗时及误报/漏报回归，才能判断收益。

第1—4项已按[实施说明](audit-workflow-optimizations-1-4.md)调整；本表保留优化前的问题证据，第5—8项中的工具探测和覆盖机械汇总已在[第二轮优化](audit-redundancy-mechanical-optimizations.md)处理；终态攻击链差异复核和政策统一仍未实施。快速动态预算与共享环境改动详见[实施说明](quick-dynamic-shared-environment.md)。
