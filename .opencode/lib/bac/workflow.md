# 越权专项集成流程

仅对冻结任务 `bac_analysis.mode=auto` / `AUDIT_BAC_MODE=auto` 启用 `bac-analysis.v1`。新建工作台任务默认启用，创建时可关闭；历史任务缺字段按关闭处理。设置与断点恢复绑定，不增加动态执行授权。

## 调度和策略准备

Recon 复用既有入口、函数、数据库 sink、敏感操作和配置清单，记录资源/角色别名、数据库命名空间及未解析入口。不要再构建全库 AST/CPG。数据库相关性未知的入口不能被删除。

Orchestrator 在分派适用 Java/Web/Python 工作包前，以独立 `security-threat-modeler` 会话准备资源组的 ACP。使用 `P03_PLAN.security-threat-modeler.acp`，`mode=acp`，输入冻结 Plan、Recon 清单路径、有限 `resource_scope` 与 `focus_area_ids`。该契约只在启用 BAC 时投影到 stage registry；同一会话不做实际路径缺失判断。策略生产者的真实 session 必须与源码生产者不同。按资源分片，复用同一范围已封存的策略与规范名映射；输入发生变化就产生新版本，不覆盖历史制品。

输出 `bac-policy-shard`，内容为本地 `extract-acp-quadruples` skill 定义的 `acp` 对象；另输出 `bac-resource-role-catalog`。它们存入 `$AUDIT_REPORTS_ROOT/bac/<audit_id>/policies/`。无可用策略、执行预算耗尽或框架事实缺失时，记录 GAP 并正常派发静态包，不等待用户。Orchestrator 不自己推断权限或补写策略。

## 专业工作包

`audit-todo claim` 中带 `bac_analysis.required=true` 的项必须交付专项结果。专业 Agent 加载 `detect-bac-risks`，Java 同时加载 `java-access-path-analysis`；Python/服务端 JS 使用 shared skill 中的对应框架说明。浏览器端代码不能证明服务端授权。

在同一真实专业会话中复用三个 lens 的事实：sink 恢复调用与输入流，config 确認生效的框架控制，control 执行差分与源码复查。保持每个 lens 的独立报告。不要向 blind 轨道传入 ACP 差分结果。

1. 使用 `prepare` 为当前工作包生成请求草稿，将已封存的策略和规范名目录并入；补全实际路径及 API 完整性。模板默认 PARTIAL，空数组不是无漏洞证明。
2. 使用 `compare`，保存不可变差分 JSON、中文 Markdown、候选 SARIF 和运行 manifest。
3. 使用 `prepare-review` 获得逐候选复查模板。检查入口绑定、身份、调用链、全局/局部/查询级控制、分支及失败行为。保留反证。
4. 逐项处置原始候选：`ACCEPTED` 携带通过 Finding v2 与 finding-details.v1 的候选；`INCONCLUSIVE` 说明缺口；`REJECTED` 提供非空 evidence 数组记录有源码定位的反证；`DUPLICATE` 只指向同次复查中 ACCEPTED 的平台 Finding。跨包去重交给 correlator。
5. 使用 `review` 封存复查；把返回的 `attachment` 原样放入 control-driven 报告的 `bac_analysis`，把返回的 findings 原样加入该报告的 `findings`。之后才提交三视角 handoff。

CLI 示例（全部路径使用注入根目录，标识取当前真实分派）：

```sh
node "$AUDIT_BAC_CLI" prepare --plan "$PLAN" --source-root "$AUDIT_SOURCE_ROOT" --reports-root "$AUDIT_REPORTS_ROOT" --focus-area "$FOCUS" --assignment "$ASSIGNMENT" --session "$SESSION" --run-id "$RUN"
node "$AUDIT_BAC_CLI" compare --request "$REQUEST" --reports-root "$AUDIT_REPORTS_ROOT"
node "$AUDIT_BAC_CLI" prepare-review --run "$BAC_RUN" --output "$REVIEW_DRAFT"
node "$AUDIT_BAC_CLI" review --run "$BAC_RUN" --review "$REVIEW_DRAFT" --reports-root "$AUDIT_REPORTS_ROOT"
```

Python 可由 `AUDIT_BAC_PYTHON` 指定原生可执行文件；不安装依赖、不执行目标源码、不使用容器。缺少解释器、超时或无效输入只影响专项，在 control-driven 报告中交付显式 GAP。若审查后确认只有非数据库/浏览器端对象，可交付有定位证据的不适用。

```json
{"contract_version":"bac-analysis.v1","status":"GAP","reason":"无法取得自定义权限库源码，不能证明此路径的控制顺序。"}
```

不适用格式为 `status=NOT_APPLICABLE`、中文 reason、非空 evidence 数组，并提供 `plan_path` 和 `source_root`；验收将核对分派 Plan 摘要及证据实际文件。证据必须指向已审查的冻结源码。不得用“不支持该语言”伪装不适用，该情况为 GAP。BAC 分析缺口不等同整个工作包未执行：合法三视角报告可以交付 DONE，专项缺口仍进入摘要与最终报告。

## Finding 绑定

每个接入候选的 `bac_source` 为 `{run_digest,candidate_id}`，`provenance.source_report_sha256` 为差分运行的 `artifact_digest`。选择当前冻结 Plan 内 control-driven 的 `JW-ACCESS-01`、`JW-ACCESS-02` 或 `JAVA-ACCESS-01` 主 check，保留其允许的维度与责任域。`prepare-review` 返回可选 check 列表，不能创建新 check 或改写 scope。源代码事实、攻击面、guards、反证、中文内容与复现设计须由专业 Agent 实际审查后填写；脚本不凭四元组伪造完整 Finding。

`state=CANDIDATE`，复现设计 `execution_status=NOT_RUN`。无独立真伪结论前不得标记确认。原候选到平台 Finding 的完整映射保存在 `review.json`；所有输入和运行制品都是持久记录。

## 缺口、汇总与恢复

`build-local-audit-summary.mjs` 重新校验每个已完成包的专项附件和候选集合，生成 `bac_analysis` 汇总，附加 residual gaps。最终生成器同源渲染中文专项章节。工作台完成门禁重新读取包证据，防止启用专项的任务遗漏结果或使用不同版本的摘要。

专项完成只描述已声明的策略/路径范围。候选数、已接入数、路径数与策略数分别统计；跨包会重复的路径/策略不称作全库唯一数。`UNMATCHED_PATH`、ACP 冲突、未决项、缺少 API、部分路径和未知控制都保留。统计归零不能代替证据。

恢复只复用摘要有效、输入版本相同的不可变 run；已 DONE 的包不改写。后续证据只能进入新建且有界的工作包；局部队列进入 FINALIZE/FINALIZE_WITH_RESIDUAL_GAPS 时照常收尾。

对同一运行重复调用 `review` 时，内容相同会返回原交付；不同内容必须使用新 run。`compare` 拒绝覆盖已有 run。核对差分算法时，可用 shared skill 的 `scripts/validate_bac_findings.py --acp <run>/acp.json --paths <run>/paths.json --api-catalog <run>/apis.json --findings <run>/bac-findings.json` 对保存的输入做确定性重算；这只验证差分内容，不替代平台的源码、分派和 Finding 绑定校验。

## 运行证据

本 CLI 永不发起动态请求。需要验证时，专业 Agent 按 `.opencode/lib/runtime-testing/workflow.md` 输出 EXPLORE/CONFIRM 包，由 Orchestrator 入队；必须已启用动态环境且完整授权原文由执行 Agent 理解并登记。缺少授权为 SKIPPED，缺少特定身份/测试数据只跳过相关验证。

水平越权使用授权测试对象及身份对照，垂直越权核对实际调用者与应有角色，写入测试要求合法清理路径。仅 Chrome DevTools MCP、授权 origins、测试数据、隔离身份。原始 BAC ID 不替代 CONFIRM 所需的平台 Finding ID 和对象摘要；所有动态支持仍走原三方复核。
