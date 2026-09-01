# 动态漏洞验证 Agent 设计方案

## 1. 目标与状态

本方案定义 `dynamic-vulnerability-validator` 的本机 Web 验证器：接受漏洞目录中
`applies_to` 包含 `web` 的类型。`JW-INJECT-06`（服务端渲染与 DOM XSS）保留专用
强校验，其余类型使用通用 Web 结果契约。

它是静态审计流程的条件旁路阶段，而不是自动化攻击功能：只有用户明确要求
动态验证并提供授权的本机 loopback 测试环境时才可以执行。账号与登录/清理步骤
按目标实际需要选填。它生成与静态 Finding 绑定的补充证据，不会自动改写静态 Finding、
裁决、攻击链或最终报告。

当前方案已确定的边界如下：

- 浏览器后端仅为 Chrome DevTools MCP；不得使用或静默回退到 `agent-browser`。
- 桌面环境优先使用可见 Chrome；无桌面的 Linux 服务器仅允许受管的隔离 headless Chrome。
- 构建和部署只使用 Windows/Linux 原生进程；禁用 Docker、Podman、Compose、容器镜像及任何容器运行回退。
- 仅允许 `localhost`、`127.0.0.1` 和 `[::1]` 的 HTTP(S) 测试目标。
- 暂不支持 Docker 容器内部域名、远程 staging、生产、第三方站点或真实用户。
- Web 目录类型已开放；不属于 Web 范围的类型仍拒绝调度。需要破坏性、拒绝服务、进程崩溃、文件覆盖或外部目标访问才能确认的步骤不得执行，应返回 `INCONCLUSIVE` 或 `NOT_RUN`。

`vulnerability-validator` 现在负责终稿前的真实性路由：任务 opt-in 时先委派
`quick-dynamic-validator` 做全任务最多 120 秒的 loopback 快速确认，再把未确认项
交给本地正方、反方、Moderator 静态挑战。本文件描述的
`dynamic-vulnerability-validator` 是另一个只由用户手动触发的完整验证 Agent；其结果
是 sidecar，不替代或自动改写上述 routing。

## 2. 总体架构

```text
静态 Finding + 静态裁决
          │
          ▼
sealed external-runtime-validation request
          │
          ├─ 用户未显式请求动态验证：不执行
          │
          └─ 用户显式请求，并在 prompt 提供本机 URL 与可选账号/操作说明
                    │
                    ▼
          primary orchestrator 创建条件阶段 handoff
                    │
                    ▼
          dynamic-vulnerability-validator
                    │
          Chrome DevTools MCP（可见、隔离 profile）
                    │
                    ▼
      target binding + result + 最小化脱敏证据 + cleanup 状态
```

动态验证位于条件阶段 `P08_RUNTIME_VALIDATION`。它不属于正常审计完成的前置条件，
也不会因存在静态 finding 或 request 而自动触发。

若缺少有效的授权测试 URL，动态验证不得启动。账号、登录或清理指令不是全局
必填项；当某个证明步骤确实依赖缺失的身份、权限边界或安全清理路径时，
`dynamic-vulnerability-validator` 对该步骤返回 `INCONCLUSIVE` 或 `NOT_RUN`，不得自行发现环境或索要凭证。

## 3. Chrome DevTools MCP

项目 `.opencode/opencode.json.bak` 和本机生成的 `.opencode/opencode.json`
配置名为 `chrome-devtools` 的本地 MCP：

```json
{
  "type": "local",
  "command": [
    "npx",
    "-y",
    "chrome-devtools-mcp@1.8.0",
    "--isolated=true",
    "--redact-network-headers=true",
    "--no-usage-statistics",
    "--no-performance-crux"
  ],
  "cwd": ".",
  "timeout": 300000,
  "enabled": true
}
```

发布配置固定为已验证的 `1.8.0`，每个验证结果仍需记录实际观测版本。动态 Runner
通过 Browser Session Broker 为当前任务覆盖这一基础 MCP 定义：低影响桌面任务可以
使用 `--auto-connect` 并创建独立 tab 或 named isolated context；Web XSS、双账号、
持久化写入、下载、权限、代理等任务必须升级为 `--isolated=true`。Linux 没有桌面
环境时，隔离实例增加 `--headless=true`。任何模式都只允许关闭 Broker 登记的 page、
context 或隔离实例，禁止通过系统级 kill Chrome/Chromium 进程重置环境。

共享标签页连接还有独立就绪门禁：Chrome 主版本必须不低于 144，用户已经为所选
profile 开启远程调试，并明确确认控制器能够看到该 profile 的其他页面。缺少任一项时
Broker 拒绝分配共享会话；即使连接成功，也不得枚举、操作或关闭未登记为本任务所有的页面。

全局配置默认拒绝 `chrome-devtools_*` 工具，只有 `quick-dynamic-validator` 与
`dynamic-vulnerability-validator` 的前置权限块可以使用它们。`initial.sh` 仅探测 MCP
的工具可用性；浏览器会在实际调用页面相关工具时以可见窗口启动。

## 4. 输入、账号与环境信息

动态验证的最小输入是：

- 已封存且通过共享校验的 `EXTERNAL_RUNTIME_VALIDATION_REQUEST`。
- claim 的漏洞类型在目录中声明 `applies_to: web`；`JW-INJECT-06` 路由到 XSS 专用验证器，其他类型路由到通用 Web 验证器。
- 当前 user prompt 中提供的 loopback 测试 URL。
- 可选账号模式：匿名、单一共享测试身份，或不同的 `attacker` 与 `victim` 身份。
- 可选的登录步骤和应用内清理步骤。

登录步骤可以引用项目或全局 Skill；Skill 只能包含流程说明，不得包含密码等凭证。
账号名、密码、验证码或其他认证数据由当前 user prompt 直接提供，只能在本次活跃
会话中使用，绝不写入 target binding、result、Skill、控制台摘录、截图名称或其他
持久化制品。

运行前，Agent 创建并密封 localhost target binding。该文件只记录授权来源、
base URL、允许 origin、账号角色、登录说明来源和清理策略；不记录任何凭证值。
校验器拒绝非 loopback URL、目标字段中的 URL 凭证、secret-shaped 字段和非用户
显式授权。只有 `distinct_test_accounts=true` 且实际使用不同隔离身份时才允许跨用户结论；
缺少安全清理路径时不得为了证明漏洞而创建持久写入。

## 5. Web-XSS 验证流程

Agent 对每个 request 只验证一个 finding，并按以下顺序工作：

1. 校验 request、target binding 和 URL 允许范围。
2. 按账号模式创建任务所需页面。只有提供两个不同身份时才分别创建隔离上下文并完成登录；
   attacker 的 cookie、storage 或页面状态不能复用为 victim 证据。
3. 在提交 payload 前保存最小化 baseline：必要的 DOM 摘录、相关 console 状态和
   脱敏请求元数据。
4. 可选地通过 CDP `evaluate_script` 写入无害 DOM marker，确认浏览器自动控制可用。
   这个结果只能标记为 `DOM_PROBE_ONLY`，永远不是应用漏洞证据。
5. 从实际输出上下文派生唯一、无害的 proof marker，通过用户指定的真实应用 UI 或
   API 提交。不得用 CDP 直接改 DOM 来伪造应用证据。
6. 观察应用重新渲染后的 marker 执行。proof marker 只能设置良性的 DOM 属性或
   内存标记；不得弹窗、外联、读取 token/cookie/个人数据、访问无关记录或建立持久化。
7. 刷新页面或离开后重新进入，确认同一 marker 再次执行。
8. 仅当提供不同 victim 身份时，才在独立 victim context 中访问相同内容并确认同一 marker
   再次执行；否则最高只能形成同身份证据。
9. 使用用户提供的应用内清理路径删除测试数据；刷新或重新访问确认是否已移除。
10. 写入最小化、脱敏的证据并通过确定性校验器密封结果。

顶层页面导航到不在允许 origin 清单内的地址时必须停止。禁止尝试通过子域、
容器 hostname、远程地址或账号切换绕过 loopback 范围。

## 6. XSS 结论分级

| 级别 | 结论要求 | 是否为优先终态 |
| --- | --- | --- |
| `DOM_PROBE_ONLY` | 仅 CDP 直接写入当前 DOM | 否；不得 `SUPPORTED_RUNTIME` |
| `APP_RENDERED_XSS` | 应用真实接收输入并渲染出可执行内容 | 否 |
| `STORED_SAME_USER` | 应用渲染的 marker 在刷新/重访后再次执行 | 否 |
| `STORED_CROSS_USER` | 独立 context、不同测试账号中也执行 | 是 |
| `NOT_CONFIRMED` | 基线、编码、可达性或执行观察与主张矛盾 | 否 |

`SUPPORTED_RUNTIME` 只能用于有应用输入和应用执行证据的后三类成功级别。
`preferred_goal_met=true` 当且仅当级别为 `STORED_CROSS_USER`。当只能证明
`APP_RENDERED_XSS` 或 `STORED_SAME_USER` 时，必须保留存储或跨用户验证缺口，
不得夸大为最终目标。

## 7. 清理与残留暴露

被存储的唯一 proof marker 是授权测试数据，不等同于允许创建后门或系统持久化。
每次验证都必须尝试通过用户授权的应用内路径清理它，并在刷新或重访后复核。

清理失败不会抹除已经充分证明的 XSS 结论。结果应当：

- 记录 `cleanup.status=FAILED` 和失败操作的最小证据。
- 写明 payload 是否在清理后仍会执行。
- 指出受影响的测试记录、页面和测试账号角色，不记录真实凭证。
- 在 `residual_gaps` 中添加人工清理动作和残留暴露。

“删除接口报告成功但刷新后 marker 仍执行”是重要的残留事实；它不自动产生新的
漏洞等级，但应由后续人工根据应用的数据生命周期和访问控制决定是否单独立项。

## 8. 制品与完整性

所有持久化结果位于：

```text
reports/validation-handoff/runtime/<audit_id>/<finding_id>.request.json
reports/validation-handoff/runtime/<audit_id>/<finding_id>.target.json
reports/validation-handoff/runtime/<audit_id>/<finding_id>.result.json
reports/validation-handoff/runtime/<audit_id>/<finding_id>/evidence/
```

`target.json` 通过 `binding_digest` 绑定到 exact request。`result.json` 同时遵守
共享 runtime-validation result contract，并增加：

- `environment_binding_digest`
- `browser_backend`：固定为 `chrome-devtools-mcp`、`chrome-devtools-mcp@1.8.0`、
  实际版本、实际 `headless` 状态及 `isolated=true`
- `xss_verification`：验证等级、proof ID、应用输入/执行、刷新、attacker/victim
  context、不同账号、victim 执行和清理状态
- `network_trace`：按时间顺序引用关键步骤的脱敏 HTTP exchange，覆盖请求方法、
  loopback URL、浏览器上下文、耗时、请求/响应 Header、最小化 Body 和响应状态。

新结果使用 `web_xss_extension_schema_version=2`。每个 exchange 独立写入
`evidence/`，遵守 `sanitized-http-exchange.schema.json`，敏感 Header 只能保存为
`[REDACTED]` 或摘要。历史 v1 结果保持可读，但观测台会显示网络证据未捕获。

通过以下脚本进行密封和校验：

```sh
node .opencode/skills/dynamic-vulnerability-validator-subagent/web-xss-runtime-validation/scripts/validate-web-xss-runtime-result.mjs \
  --request <request> --target <target> --result <result> --seal
```

结果是补充制品，永远不自动修改原 Finding、独立裁决、攻击链和最终报告。若要把
动态证据导入这些制品，需要单独定义后续的人工审批与导入流程。

## 9. 权限和行为约束

根目录 `AGENTS.md` 是全项目动态验证硬边界。动态验证 Agent 在自身 frontmatter
中再次实现最小权限：

- 仅开放 `chrome-devtools_*` MCP 和两个固定的 Node 校验脚本。
- 仅允许写入 runtime-validation target、result 和 evidence 目录。
- 禁止 web search、web fetch、外部目录、子 Agent、LSP 和任意 Bash。
- 禁止访问非 loopback 目标、真实用户、无关 tenant、生产和第三方服务。
- 禁止 `pkill`、`killall`、通配 PID 终止、`taskkill`、`Stop-Process` 等全局
  Chrome 重置方式。
- 禁止 `agent-browser`。

会话无法通过关闭 MCP 创建的页面或 context 恢复时，必须报告 `BLOCKED`，由用户
处理浏览器环境；Agent 不得尝试升级为系统进程管理。

## 10. 代码与配置变更清单

实现由以下部分组成：

- `AGENTS.md`：项目级动态验证安全边界。
- `.opencode/opencode.json.bak`：Chrome DevTools MCP 模板与默认 deny 权限。
- `.opencode/agents/dynamic-vulnerability-validator.md`：Agent 的输入、权限、
  工作流和输出边界。
- `.opencode/skills/dynamic-vulnerability-validator-subagent/`：集合、Web-XSS
  Skill、target binding schema、结果契约和确定性校验脚本。
- `.opencode/agent-manifest/{roles,mcp-map,skill-map,artifact-policy}.json`：角色、
  MCP 路由、Skill 映射和动态制品策略。
- `.opencode/skills/common-subagent/audit-artifact-management/contracts/stage-agent-contracts.json`：
  条件阶段 `P08_RUNTIME_VALIDATION` 的 I/O contract。
- `.opencode/agents/security-audit-orchestrator.md`：仅在显式请求、信息完整时的
  dispatch 规则，以及缺失信息时仅主 Agent 可询问的规则。
- `README.md`、`docs/installation.md`、`initial.sh`：安装、健康检查和使用说明。
- `.opencode/web/dynamic-validation-observatory/`：动态 core、Browser Session Broker 与
  本机 Web 服务，聚合 runtime 结果并只读展示、筛选和导出脱敏请求证据链。
- `.opencode/scripts/dynamic-validation-cli.mjs`：独立 `doctor`、`run`、`list`
  和 `serve` 入口，不依赖静态审计队列。

## 11. 验证与验收

默认回归必须不访问任何浏览器或测试环境，至少覆盖：

- 基础配置使用固定 Chrome DevTools MCP 版本和隔离模式；Broker 的共享连接、隔离
  context 与 Linux headless 决策分别经过策略测试。
- 平台不暴露人工发送、改包、重放或取消请求的接口；发包记录来自动态验证的浏览器网络
  证据并保持只读，HAR/OpenCollection 导出会再次执行脱敏，人工操作交给 Bruno。
- 浏览器网络证据使用 `HTTP_EXCHANGE_V2`；历史 v1 浏览器工件只在读取时
  转换，新的 Web-XSS 证据必须携带 `source=chrome_devtools_mcp` 和 `evidence_binding`。
- 全局默认拒绝 Chrome MCP，只有快速动态与人工完整动态两个验证 Agent 拥有对应工具权限。
- 非 loopback target、含凭证字段的 target binding、缺少用户显式授权、缺少两个
  不同测试账号或缺少清理说明都会被拒绝。
- `DOM_PROBE_ONLY` 不得形成 `SUPPORTED_RUNTIME`。
- 没有刷新/重访证据不得声称 stored XSS。
- 相同 attacker/victim context 不得声称跨用户影响。
- 清理失败必须带有残留缺口；带完整残留记录的结果可以通过校验。

这些门禁由 `npm run test:dynamic-validation-contract` 和配置验证回归执行。

在用户提供本机测试环境后，可额外执行人工或专用 E2E 冒烟验证：创建两个隔离
测试会话，验证安全 marker 的存储、刷新、victim 执行和清理路径；该验证不能作为
默认 `npm test` 的前提。

## 12. 后续演进（不在本期范围）

以下事项需要重新进行设计、审批和落地，不能通过放宽当前 Agent prompt 临时启用：

- 支持 Docker 容器内部 hostname 或远程 staging。
- 使用 `agent-browser` 作为并行或替代浏览器后端。
- 为代码执行、文件覆盖、资源耗尽或进程崩溃增加允许破坏性确认的验证模式。
- 将 runtime result 自动或半自动导入 adjudication、attack-chain 或 final report。
- 允许持久化测试账号配置、秘密管理集成或非本机浏览器调试端口。
