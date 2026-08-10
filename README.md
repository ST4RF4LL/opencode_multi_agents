# OpenCode Multi-Agent Source Security Audit

这是一套项目级 OpenCode 配置，用于对源码、平台配置以及 AI/LLM/Agent/RAG/MCP 系统做多 agent 安全审计。系统先从代码、文档、历史漏洞和 Owner 知识构建可追溯威胁模型，再按入口点、信任边界、资产和业务/AI 工作流划分 Focus Area。每个 Focus Area 的适用 D1-D10 维度都经过 `sink-driven`、`control-driven`、`config-driven` 三个视角，并补充 checklist-light Blind、历史/案例驱动的 Seeded Variant 和独立系统攻击链发现。可信结构 verifier 对文件/函数做精确差分；Coverage Telemetry 以 Assignment Unit 接收 exception-first 证明，在 Ledger 内部保留精确 check 状态和认证哈希链；语义 verifier 对入口点/威胁/Focus/发现轨道/攻击链面做精确差分。

首次使用请先完成[初始化与安装](docs/installation.md)，生成仅保存在本机的 `.opencode/opencode.json`。

## Agent topology

- `security-audit-orchestrator`: 主控入口，负责生成单视角任务包、维护覆盖立方体、执行门禁并汇总报告。
- `security-intel-collector`: 信息收集，输出攻击面、语言/平台路由及五类标准化清单（含 AI surface）。
- `security-threat-modeler`: 从代码、历史和 Owner 知识生成可追溯威胁模型，并把完整基础/AI 审计全集划分为确定性 Focus Area。
- `c-cpp-source-auditor`: 以单一 Tri-Lens 策略执行 C/C++ 源码审计。
- `java-source-auditor`: 以单一 Tri-Lens 策略执行 Java/JVM 源码审计。
- `web-source-auditor`: 以单一 Tri-Lens 策略执行浏览器 JS/TS、HTML、JSP 和模板源码审计。
- `python-source-auditor`: 以单一 Tri-Lens 策略执行 Python 源码审计。
- `platform-security-auditor`: 审计依赖、构建、CI/CD、容器、编排、网关和 IaC 等语言无关平台面。
- `ai-security-auditor`: 对全部冻结文件和函数执行 AI 专项第二覆盖层，审计 LLM、Agent、RAG、Memory、MCP/Tool、模型/数据供应链、训练评测和模型制品。
- `security-evidence-correlator`: 归一化覆盖、合并跨视角证据、去重、暴露矛盾/GAP 并生成补充任务。
- `security-attack-chain-hunter`: 在分区审计后执行独立系统级发现，覆盖全部 Focus Area、信任边界和资产。
- `dynamic-vulnerability-validator`: 仅在用户显式要求时，使用可见、隔离的 Chrome DevTools MCP 对 localhost 上的 `JW-INJECT-06` Web-XSS 做动态验证，优先证明刷新后仍存在且影响第二测试账号的 stored XSS。
- `vulnerability-validator`: 在最终综合报告封存后，将整份报告一次性交给 `vuln_judger`，监控 OpenCode 驱动的正方/反方/主持人三方复核并保存伴随制品。
- `security-skill-optimizer`: 根据已完成的三方复核结果优化审计 skill、Joern 规则、漏洞案例和误报案例。

为降低大型仓库的威胁分析前置耗时，Recon 默认使用 Git tracked + untracked/non-ignored 范围，Joern 只解析对应语言的临时源码投影，函数清单按 scope digest 自动复用，并额外生成紧凑的 `threat-routing-index.json`。威胁建模默认只执行一次 bootstrap，消费制品路径与紧凑索引，不重复运行 `.mjs` 构建器；只有已提供 Owner 答案或明确要求访谈时才执行 refine。

## Tri-Lens coverage

三个视角是任务模式，不是互斥的漏洞类型归属：

- `sink-driven`: 定位安全敏感操作并追踪攻击者影响和可达性。
- `control-driven`: 枚举敏感操作并验证应该存在的安全控制。
- `config-driven`: 确定实际生效的配置、依赖和部署选择并对照基线。

Orchestrator 为每个 `Focus Area × owner/domain assignment` 建立一个内容寻址的 Coverage Unit；三个 lens 是 unit 内部维度，仍可由独立 session 执行。目录和接口关系保留为 unit 内部精确 check，但正常路径只调用 `coverage_get_unit`、`coverage_begin_unit` 和一次 all-minus-gaps attestation，不再逐 check 领取、回执、决策。Attestation 只证明执行覆盖，不声明 `NO_FINDING`；真实 finding、gap 分类或定点返工可在前后独立绑定精确 check。完整成员列表不会进入正常 MCP 响应，subagent 也不能直接修改 canonical Ledger。

Coverage policy 分为 `observe`（默认，只记录不阻塞）、`release`（仅门禁带策略标签的 AI/外部接口/身份权限 unit）和 `assurance`（严格全覆盖）。策略验收与完整覆盖声明分离：即使 observe 流程完成，剩余 gap 仍以 `PARTIAL`/`BLOCKED` 和精确 `R/V/U/N` 呈现，绝不会伪装成 `COMPLETE`。统计同时给出 unit 执行率、lens/关系覆盖、证据覆盖和 inventory 状态。

## Skill management

Skill 按 subagent 分组，目录结构固定为 `.opencode/skills/<subagent-skill-group>/<skill-name>/SKILL.md`，例如 `.opencode/skills/c-cpp-subagent/c-cpp-memory-safety-review/SKILL.md`。分组目录本身不包含 `SKILL.md`，只放 `collection.json` 和维护说明，OpenCode 会递归发现子目录中的原子 skill。

### 自动映射

Skill 到 agent 的映射通过目录约定和 `collection.json` 自动完成，无需手动同步多个文件：

- **`collection.json`** — 每个 skill 分组目录下的唯一 skill 清单，其中的 `owner_agent` 字段定义了该组 skill 归属的 agent。
- **`skill-map.json`** — 文档参考，记录所有 `collection → owner_agent` 映射关系，不再重复维护 skill 列表。
- **agent frontmatter** — 所有 agent 的 `skill` 权限已统一设为 `"*": allow`，任意 skill 被发现后即可使用。

> 新增 skill 只需：放入对应分组目录 → 创建 `SKILL.md` → 将 skill 名称加入 `collection.json`。无需修改其他配置文件。

### 命名前缀约定

| 角色 | 推荐前缀 |
|------|----------|
| 信息收集 | `recon-*`, `intel-*`, `dependency-intel-*`, `attack-surface-*` |
| 威胁建模/分区 | `threat-*`, `evidence-backed-threat-*`, `focus-area-*` |
| C/C++ 审计 | `c-cpp-*`, `cpp-*`, `native-security-*`, `memory-safety-*` |
| Java/JVM 审计 | `java-*`, `jvm-*`, `spring-security-*`, `deserialization-*` |
| Web 源码审计 | `web-*`, `javascript-*`, `typescript-*`, `browser-security-*` |
| Python 审计 | `python-*`, `py-*`, `django-security-*`, `flask-security-*`, `fastapi-security-*` |
| 平台审计 | `platform-*`, `container-*`, `cicd-*`, `iac-*`, `supply-chain-*` |
| AI 专项审计 | `ai-*`, `llm-*`, `agentic-*`, `rag-*`, `mcp-security-*` |
| 证据关联 | `tri-lens-*`, `evidence-correlation-*`, `coverage-*` |
| 系统攻击链 | `attack-chain-*`, `system-attack-*` |
| 漏洞验证 | `validation-*`, `poc-*`, `exploitability-*` |
| Skill 优化 | `optimization-*`, `skill-optimization-*`, `joern-rule-*`, `audit-casebase-*` |

## Maintain skills and MCP

可维护性核心在 `.opencode/agent-manifest/`：

- `roles.json` — 角色边界和输入输出。
- `skill-map.json` — collection 到 agent 的映射关系（文档参考）。
- `mcp-map.json` — 每个 subagent 可用的 MCP 工具通配符。
- `artifact-policy.json` — 报告格式、临时目录和清理策略。
- `naming.md` — 新增 skill/MCP 时的命名和维护规则。

可提交的配置源是 `.opencode/opencode.json.bak`；`.opencode/opencode.json` 由每位使用者从模板生成并填写本机工具路径，不进入 Git。添加自有项目 MCP 时，先更新模板，再在 `mcp-map.json` 和对应 agent frontmatter 的权限中加入 `<server>_*`。

## Shared audit assets

公共审计资产位于 `.opencode/shared/security-audit/`，所有 subagent 都可以读取：

- `joern-rules/`: Joern 规则、规则说明和规则索引。
- `vulnerability-cases/`: 已确认或高可信漏洞案例。
- `false-positive-cases/`: 误报案例和规则收敛依据。
- `rule-results/`: Joern/静态扫描结果摘要，用于后续优化。
- `catalogs/`: 版本化漏洞覆盖目录；当前 `application-ai-vulnerability-catalog.json` 对齐应用、平台及 AI/LLM/Agent/RAG/MCP 风险，并融入 OWASP AI Agent Security Cheat Sheet 的高影响动作审批、多 Agent 通信、AI 控制台配置和对抗测试门禁要求，为三视角分别提供检查问题。

默认只有 `security-skill-optimizer` 负责修改这些资产。Orchestrator 只根据已完成且绑定最终报告摘要的 vuln-judger 复核结果决定是否拉起它：

- `TRUE_POSITIVE`: 优化相关 `SKILL.md`、补充/收敛 Joern 规则、加入漏洞案例。
- `FALSE_POSITIVE`: 加入误报案例，并收敛 skill 或规则。
- `INCONCLUSIVE`: 仅在缺失条件明确时补充证据要求，不提升为确认案例。
- `partial/failed/stopped/invalidated`: 记录复核缺口，不执行依赖结论的知识提升。

## Temporary artifacts and reports

所有**持久交付件**输出到工作区根目录的 `reports/`（不是 `tmp/`，也不是被审计应用/测试源码树内部）。临时产物存放在 `tmp/` 下按 `audit_id` 分目录管理。`tmp/` 与 `reports/**` 被 `.gitignore` 忽略；`tmp/` 只保留 `tmp/.gitkeep` 和 `tmp/README.md` 作为目录占位。

约定路径：

- 最终可读审计报告：`reports/final/security-audit-report.<audit-id>.md`
- 静态分析报告（SARIF 2.1.0）：`reports/sarif/<agent-name>.<agent-session-id>.sarif`
- 漏洞挖掘结果（JSON）：`reports/vulnerability-mining/<agent-name>.<agent-session-id>.audit-report.json`
- Blind/Seeded 发现结果：`reports/vulnerability-mining/<agent-name>.<agent-session-id>.discovery.json`
- 系统攻击链结果：`reports/attack-chains/security-attack-chain-hunter.<audit-id>.r<round>.json`
- 关联结果（JSON）：`reports/correlation/security-evidence-correlator.<audit-id>.r<round>.json`
- 覆盖验收结果（JSON）：`reports/coverage/coverage-verification.<audit-id>.json`
- 冻结 Coverage Plan：`reports/coverage/coverage-plan.<audit-id>.json`
- 服务持有的追加式 Ledger：`reports/coverage/<audit-id>/ledger/coverage-ledger.jsonl`
- v1 文件/函数结构中间结果：`reports/coverage/coverage-structural-v1.<audit-id>.json`
- 机器生成覆盖摘要：`reports/coverage/coverage-summary.<audit-id>.json`
- 与 JSON 精确同源的覆盖摘要：`reports/coverage/coverage-summary.<audit-id>.md`
- 语义覆盖验收结果：`reports/coverage/semantic-coverage-verification.<audit-id>.json`
- vuln-judger 结构化三方复核：`reports/validation/vuln-judger-review.<audit-id>.json`
- vuln-judger 可读三方复核：`reports/validation/vuln-judger-review.<audit-id>.md`
- localhost 动态验证绑定/结果：`reports/validation-handoff/runtime/<audit-id>/<finding-id>.{target,result}.json`
- 可复核覆盖输入快照：`reports/coverage/<audit_id>/inputs/{snapshot-index,scope-manifest,functions-*,interface-manifest,interface-extractor-coverage,application-ai-vulnerability-catalog,threat-model,focus-areas}.json`
- 侦察/威胁清单：`tmp/<audit-id>/recon/{entry-points,sinks,sensitive-operations,config-surfaces,ai-surfaces,recon-summary,threat-model,focus-areas}.json`
- 冻结范围、函数全集、外部接口全集、接口提取验证和威胁路由索引：`tmp/<audit-id>/recon/coverage/{scope-manifest,functions-*,interface-manifest,interface-extractor-coverage,threat-routing-index}.json`
- 临时文件、脚本、规则：`tmp/<audit-id>/`

一个 agent session 对应一个 SARIF；一个漏洞挖掘 session 对应一个 JSON。多个静态分析工具在同一 session 内运行时，应合并到同一个 SARIF 的多个 `runs`。

Orchestrator 在可信结构、v3 Ledger/统计和语义门禁后把最终 Markdown 写到 `reports/final/` 并计算 SHA-256。随后 `vulnerability-validator` 只把这份完整且不可变的报告提交一次给 vuln-judger，固定使用 `engine=opencode`，通过同一 `run_id` 异步轮询，而不是按 finding 重复调用。三方复核结果写入 `reports/validation/`，不回写已受审报告。流程**不会自动删除 `tmp/`**；`tmp/<audit-id>/` 的清理由人工处理。

## Usage

按[初始化与安装](docs/installation.md)生成本地配置后，在需要审计的源码项目根目录设置 `OPENCODE_CONFIG="$PWD/.opencode/opencode.json"` 并运行 OpenCode；也可以把整个 `.opencode/` 复制到目标项目再生成其本地配置。

推荐入口：

```text
@security-audit-orchestrator 对当前项目做一次 Tri-Lens 安全审计，完成可信结构、v3 Ledger/统计和语义覆盖门禁并封存最终综合报告，再将整份报告交给 vuln_judger 使用 OpenCode 三方执行引擎复核。
```

也可以分阶段调用：

```text
@security-intel-collector 识别当前项目的攻击面和语言路由。
@security-threat-modeler 基于冻结 Recon、代码历史和 Owner 信息建立威胁模型与 Focus Area。
@c-cpp-source-auditor 审计 native/C/C++ 安全问题。
@java-source-auditor 审计 Java/JVM 安全问题。
@web-source-auditor 审计 JavaScript/TypeScript、HTML、JSP 和模板安全问题。
@python-source-auditor 审计 Python 安全问题。
@platform-security-auditor 使用 config-driven 策略审计部署、CI/CD、容器和 IaC。
@ai-security-auditor 使用 sink-driven 策略对全部冻结文件和函数执行 AI 专项覆盖。
@security-attack-chain-hunter 对已完成的 Focus Area 结果执行系统级跨边界攻击链挖掘。
@security-evidence-correlator 关联当前 audit_id 的三视角结果并生成覆盖缺口。
@dynamic-vulnerability-validator 使用当前 prompt 提供的 localhost 测试环境、两个测试账号和登录/清理步骤，对一个已封存的 JW-INJECT-06 runtime-validation request 做可见浏览器动态验证。
@vulnerability-validator 将 reports/final/security-audit-report.<audit_id>.md 整份提交给 vuln_judger，使用 OpenCode 三方执行引擎复核并保存伴随报告。
@security-skill-optimizer 根据已完成的 vuln-judger 三方复核结果优化 skill、Joern 规则和案例库。
```

### OpenCode 安全审计工作台

统一 Web 工作台会从 `reports/` 重建 repo 级审计任务、阶段、覆盖率、canonical findings、动态验证与最终报告视图。默认以只读模式启动，不会执行审计：

```sh
npm --prefix .opencode run start:audit-workbench
```

默认监听 `http://127.0.0.1:4173`。页面统一展示服务端白名单仓库、审计任务、8 阶段流水线、漏洞台账、报告记录、Agent 运行时，以及动态验证的授权 loopback 环境、隔离浏览器上下文和 extension-v2 脱敏 HTTP 请求/响应证据链。历史 v1 验证结果没有持久化 HTTP exchange 时会明确标记为“未捕获”。

需要由 Web 端启动 OpenCode 时，必须显式开启 Runner，并在服务端登记允许审计的仓库。仓库需要是已 checkout 的 Git 工作树，且包含生成好的 `.opencode/opencode.json`：

```sh
npm --prefix .opencode run start:audit-workbench -- \
  --enable-runner \
  --repo payment=/absolute/path/to/payment-service \
  --repo iam=/absolute/path/to/iam-service
```

浏览器只提交仓库 ID、audit ID 和 Git ref；服务端不会接收任意路径或 shell 命令，也不会自动 checkout。默认拒绝脏工作树和未位于目标 ref 的仓库。运行日志、状态和有序事件写入服务端管理的 `reports/platform/audit-runs/`，SSE 用于实时刷新。暂停、恢复和取消只作用于工作台自己创建的 OpenCode 子进程。

若还需要从 Web 调度动态验证，必须额外显式启用动态 Runner：

```sh
npm --prefix .opencode run start:audit-workbench -- \
  --enable-runner \
  --enable-dynamic-validation \
  --repo application=/absolute/path/to/application
```

动态页面只允许调度已经密封且尚无结果的 `JW-INJECT-06` request。操作员必须在表单中再次确认 localhost 授权测试环境，提供两个不同的专用测试账号及登录/清理步骤。凭证进入独立的临时 OpenCode 数据目录；日志按实际提交值再次脱敏，进程结束后删除整个临时会话目录。服务不会杀死或重置全局 Chrome 进程。

可使用 `--port` / `AUDIT_WORKBENCH_PORT` 修改端口；服务拒绝监听非 loopback 地址。原有 `start:dynamic-validation-web` 命令作为兼容别名保留。详见 [Web 工作台架构](docs/audit-workbench.md)。创建静态审计任务不会自动触发动态验证；只有操作员在动态验证表单中的单独显式提交才构成调度请求。

## Local analysis and MCP defaults

Semgrep/OpenGrep 不再注册为 MCP。Agent 通过 `node .opencode/scripts/semgrep-scan.mjs` 直接调用受控扫描入口：`health` 检查本地引擎，`scan` 自动优先使用 `opengrep` 并回退 `semgrep`，只接受工作区内本地 YAML 规则。完整 JSON 与 stderr 保存到 `tmp/<audit_id>/semgrep/`，结果归一化并合并到 `reports/sarif/`，终端只输出不超过 16 KiB 的摘要。扫描器的异常 JSON 也有 64 MiB 硬上限。

Joern 不再注册为 MCP。函数清单构建器和审计命令直接调用 `joern-parse` 与 `joern`；默认从 `PATH` 解析，也可在启动 OpenCode 前通过 `JOERN_BIN`、`JOERN_PARSE_BIN`、`JOERN_JAVA_BIN` 和 `JOERN_GNUBIN` 指定本机工具链。Joern 查询应把完整 stdout/stderr 写入 `tmp/`，只把有界摘要带回 agent 上下文。

配置模板默认启用 `coverage_ledger` 和 `chrome-devtools`。后者使用 `npx -y chrome-devtools-mcp@latest` 启动可见、隔离的本机 Chrome，只对 `dynamic-vulnerability-validator` 开放；当前不支持远程、容器域名、headless 或 `agent-browser` 回退。`coverage_ledger` 暴露 Assignment Unit、attestation 和兼容的 check 级工具，串行生成认证哈希链。正常 unit 工作流仅交换计数、事件元数据和服务端派生的冻结 source-set 摘要，单次响应硬限制为 16 KiB；完整 source/接口元数据仅允许按小页做定向诊断。

`context7`、`gh_grep`、CodeQL 以及 `vuln_judger` / `vuln-judger` MCP 占位均已从项目配置中删除。历史 CodeQL 规则文件仅作为离线知识资产保留，不会被 agent 调用。`vuln_judger` 服务完全由用户的全局 OpenCode 配置提供；项目只保留 validator 的工具前缀权限与路由契约，`judge_report` 必须传 `engine=opencode` 且异步轮询。`cpp_index`、`jvm_index`、`python_index` 和 `audit_lab` 仍是可替换占位。

占位 MCP 需要替换为你本机实际可运行的 `type/command` 或 `type/url` 后再启用。

## Permission defaults

默认配置已放开编辑和外部访问权限，便于开发和调试：

- `security-audit-orchestrator` 使用 catch-all `allow` 覆盖全局默认：所有内置、Skill、自定义及 MCP 工具均自动放行，不需要用户手动确认；canonical Ledger 直接写入是硬拒绝，只能走本地 MCP。
- 全局使用 `"*": "allow"` 兜底，`bash` 与 `task` 默认自动放行；所有 subagent 的 Bash catch-all 同样为 `allow`，执行期间不会发起权限确认。
- 各 agent 原有的显式 `deny` 保持不变：不适用或越界工具会直接拒绝，而不是请求用户确认。
- 大多数开发用 agent 保留现有编辑能力；`ai-security-auditor` 仅允许写入 `tmp/` 与 `reports/`。
- `external_directory: allow`, `webfetch: allow`, `websearch: allow` — 允许外部目录访问和网络操作。
- `skill: "*": allow` — 所有 agent 可使用任意发现的 skill，skill 通过目录约定自动映射。
- `pwd`、`ls`、`find`、`rg`、`git status/log/grep/ls-files`、`mkdir` 等既有细粒度规则继续保留，便于描述各角色的常规命令集；未命中的 Bash 命令也自动允许。
- `vulnerability-validator` 只负责封存报告的 vuln-judger 三方复核；独立的 `dynamic-vulnerability-validator` 只在显式授权后验证 localhost Web-XSS，并禁止生产/第三方目标、全局 Chrome 进程终止、凭证持久化、外连利用或数据窃取。
