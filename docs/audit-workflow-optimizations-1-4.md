# 审计流程前四项优化实施

本次处理冗余分析中的第1—4项；快速动态仍保留共享准备240秒、每报告180秒。以下描述代码行为，不代表已测得性能收益。

## 1. 新任务完成门禁统一

新任务继续使用 `TODO_ENFORCED`：本地工作项全部 DONE/GAP，且最终中文报告就绪，才可完成。八阶段注册表改为 `ACTIVE/SHADOW`，只提供证据展示，缺少阶段封口不再要求重新执行终态工作包。orchestrator、交付 Skill 和文档已取消相反要求。

历史 `ENFORCED` 分支保留，并读取 `contracts/legacy-enforced-v1/` 的原有固定注册表与 Stage/Agent 契约，避免新展示政策导致旧摘要绑定失效。历史契约不能反过来成为新任务门禁。

## 2. 一个会话完成三视角，一个 handoff 绑定全部结果

新 Coverage Plan 标记 `packet_report_contract=tri-lens-v2`。每个工作项在同一次专业 Agent 会话中完成 sink/control/config，复用源码定位和上下文；各视角仍分别保留原来的 `audit_strategy`、实体证据和覆盖数组。

DONE 交付格式示例（路径相对 reports 根）：

```json
{
  "item_id": "todo:<unit-id>",
  "status": "DONE",
  "reports": [
    { "lens": "sink-driven", "path": "vulnerability-mining/<session>.<focus>.sink.audit-report.json", "sha256": "<文件摘要>" },
    { "lens": "control-driven", "path": "vulnerability-mining/<session>.<focus>.control.audit-report.json", "sha256": "<文件摘要>" },
    { "lens": "config-driven", "path": "vulnerability-mining/<session>.<focus>.config.audit-report.json", "sha256": "<文件摘要>" }
  ]
}
```

控制器检查三个视角齐备、路径在 reports 内、普通文件、摘要有效、audit/Focus/assignment/Agent/source scope 绑定一致，并要求同一实际 session ID。finding IDs 从报告读取，不采纳 handoff 中任意增加的 ID。任何视角未完成可写 GAP，但不能用一份报告冒充三视角 DONE。

TODO 持久化完整 `report_bindings`；裁决输入和本地汇总再次验证绑定后消费全部报告。旧 Plan/TODO 的单个 `artifact_path` 仍按旧模式读取，不擅自转换历史 DONE。Stage/Agent 的单视角 envelope 作为同一调用内的证据记录，不表示必须再启动三次会话。

## 3. 复用不可变事实包，保留独立结论

没有删除初步语义裁决或三方角色，也没有降低初步支持结论的既有证明门槛。Intake builder 从已通过校验的候选和裁决生成 `static-fact-packet`，保存源码事实、语义路径、保护措施、影响与不确定性；绑定 finding、候选/裁决摘要、scope 和 round。

事实包位于 `reports/validation/facts/<audit-id>/r<round>/<内容摘要>.json`，以只创建方式写入，相同内容可复用、不同内容不能覆盖。Intake 引用其路径、摘要和最低复核模式。

- `TARGETED`：复用事实获取结果。正方核查关键证明链，反方独立选择并验证反证，Moderator 针对争议与影响闭合回源；不重复全量扫描和无变化的长篇证据重述。
- `FULL`：存在不确定性、矛盾、非高置信证据、跨租户/跨服务/供应链影响或影响范围未知时，控制器要求完整复核。角色发现新争议或重大影响时也必须主动升级。

三方仍用不同会话、独立给结论，并记录 `fact_packet_digest`、`review_mode`、`checked_evidence_refs`。校验器拒绝降级 FULL、缺少回源记录或绑定其他事实包。routing、最终模型构建与整包验证均检查事实包实际内容；历史无事实包 intake 保持原有完整复核路径。

因此减少的是重复取证和无争议部分的重建成本，而非通过共享上游标签快速判真。尚未声称减少固定角色调用次数。

## 4. AI 深审按表面、依赖与样本选择

Recon 仍检查全仓的 AI 适用性，但不要求 AI Agent 对所有文件再深审一遍。先写与 scope digest 绑定的 `ai-applicability-decisions.json`：每个可审查文件恰好一项，含 file_id、state、reason、evidence_refs、depends_on_file_ids。状态为 RELEVANT、DEPENDENCY、NOT_APPLICABLE 或 UNKNOWN。证据必须引用冻结源码路径，可附行号；负面判断不能仅以“关键词没命中”为依据。

在下游快照和 Focus 划分之前运行：

```text
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-ai-coverage-routing.mjs --scope <scope-manifest.json> --decisions <ai-applicability-decisions.json>
```

构建器将相关/依赖/未知文件及双向依赖闭包纳入选择；对剩余负面文件按 scope digest 确定性抽取10%，最多5个。样本用于发现筛查遗漏，不提供统计意义上的“全仓无 AI 风险”保证。

范围记录 `ai_routing`，并绑定每个文件摘要。路由索引、Focus 分区校验、Plan、报告初始化、文件/函数结构校验和语义校验均消费同一选择。未选负面文件不再需要 AI 覆盖记录，也不会被改写为 AI PASS。UNKNOWN 始终保留 GAP，并进入本地汇总和最终中文报告；即使 TODO 全部 DONE，也只能生成带缺口的 PARTIAL/policy-final 报告。

新 Web 任务通过 `AUDIT_AI_ROUTING_POLICY=surface-dependency-v1` 要求先完成筛查；历史 scope 没有新政策时，保持原全量覆盖解释。抽查发现新 AI 表面时必须重新路由并使受影响的下游绑定失效，不能沿用旧排除结论；当前不自动重开已终态 TODO。

## 检查与待验证范围

新增回归用例覆盖三视角完整性、摘要漂移、实际会话绑定、finding ID 来源、AI 依赖闭包/负面抽样/未知项/旧策略兼容，以及事实包不可覆盖、失效拒绝和 FULL 不可降级。Windows/Linux CI 已接入相关测试。

当前编辑主机是 macOS，按照项目“在 Windows/Linux 原生主机测试和运行”的约束，仅进行了 JavaScript 语法、JSON/YAML、注册表摘要及差异静态检查；没有执行平台行为测试或真实审计。性能收益与新协议的模型执行表现仍需在受支持主机上验证。
