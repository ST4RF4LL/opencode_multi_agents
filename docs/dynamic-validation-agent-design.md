# 动态漏洞验证 Agent 设计方案

## 1. 目标与状态

本方案定义 `dynamic-vulnerability-validator` 的首个可用验证器：针对
`JW-INJECT-06`（服务端渲染与 DOM XSS）的显式、授权、本机动态验证。

它是静态审计流程的条件旁路阶段，而不是自动化攻击功能：只有用户明确要求
动态验证，且提供完整的本机测试环境、两个测试账号、登录步骤和清理步骤时，
才可以执行。它生成与静态 Finding 绑定的补充证据，不会自动改写静态 Finding、
裁决、攻击链或最终报告。

当前方案已确定的边界如下：

- 浏览器后端仅为 Chrome DevTools MCP；不得使用或静默回退到 `agent-browser`。
- 使用可见 Chrome，便于构建和调试阶段观察；不使用 headless。
- 仅允许 `localhost`、`127.0.0.1` 和 `[::1]` 的 HTTP(S) 测试目标。
- 暂不支持 Docker 容器内部域名、远程 staging、生产、第三方站点或真实用户。
- 初期只支持 Web XSS；其他漏洞类型保持 `NOT_RUN`，以后单独设计和开放。

现有的 `vulnerability-validator` 继续只负责最终报告的 vuln-judger 三方复核。
动态验证器是另一个独立 Agent，不重命名、不替代前者。

## 2. 总体架构

```text
静态 Finding + 静态裁决
          │
          ▼
sealed external-runtime-validation request
          │
          ├─ 用户未显式请求动态验证：不执行
          │
          └─ 用户显式请求，并在 prompt 提供本机 URL、账号、登录和清理步骤
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

若用户已明确要求动态验证但缺少测试 URL、两个账号、登录或清理指令，只有
`security-audit-orchestrator` 可以暂停并向用户追问；
`dynamic-vulnerability-validator` 必须返回 `BLOCKED`，不得自行发现环境或索要信息。

## 3. Chrome DevTools MCP

项目 `.opencode/opencode.json.bak` 和本机生成的 `.opencode/opencode.json`
配置名为 `chrome-devtools` 的本地 MCP：

```json
{
  "type": "local",
  "command": [
    "npx",
    "-y",
    "chrome-devtools-mcp@latest",
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

使用 `@latest` 是明确产品决定。为保持证据可追溯性，每个验证结果必须记录本次
实际观测到的 MCP 版本；不能假设不同日期的工具行为相同。

不得加入 `--headless`、`--autoConnect`、`--browser-url`、`--ws-endpoint`
或持久化 `--user-data-dir`。`--isolated=true` 必须创建临时 profile，避免访问
用户的日常浏览器 profile。浏览器状态恢复只允许关闭本次 MCP 创建的 page 或
isolated context；禁止通过系统级 kill Chrome/Chromium 进程重置环境。

全局配置默认拒绝 `chrome-devtools_*` 工具，只有动态验证 Agent 的前置权限块
可以使用它们。`initial.sh` 仅探测 MCP 的工具可用性；浏览器会在实际调用页面
相关工具时以可见窗口启动。

## 4. 输入、账号与环境信息

动态验证的最小输入是：

- 已封存且通过共享校验的 `EXTERNAL_RUNTIME_VALIDATION_REQUEST`。
- claim 为 `JW-INJECT-06`。
- 当前 user prompt 中提供的 loopback 测试 URL。
- 两个不同的授权测试账号：`attacker` 与 `victim`。
- 可执行的登录步骤和应用内清理步骤。

登录步骤可以引用项目或全局 Skill；Skill 只能包含流程说明，不得包含密码等凭证。
账号名、密码、验证码或其他认证数据由当前 user prompt 直接提供，只能在本次活跃
会话中使用，绝不写入 target binding、result、Skill、控制台摘录、截图名称或其他
持久化制品。

运行前，Agent 创建并密封 localhost target binding。该文件只记录授权来源、
base URL、允许 origin、账号角色、登录说明来源和清理策略；不记录任何凭证值。
校验器拒绝非 loopback URL、目标字段中的 URL 凭证、secret-shaped 字段、非用户
显式授权、非两个不同测试账号或没有清理说明的绑定。

## 5. Web-XSS 验证流程

Agent 对每个 request 只验证一个 finding，并按以下顺序工作：

1. 校验 request、target binding 和 URL 允许范围。
2. 为 attacker 与 victim 分别创建不同的命名 `isolatedContext`，并分别完成登录。
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
8. 在独立 victim context 中，以不同授权测试账号访问相同内容，确认同一 marker
   再次执行。
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
- `browser_backend`：固定为 `chrome-devtools-mcp`、`chrome-devtools-mcp@latest`、
  实际版本、`headless=false`、`isolated=true`
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
- `.opencode/web/dynamic-validation-observatory/`：只读本机 Web 服务，聚合 runtime
  结果并展示环境、Bug、观察与请求/响应证据链。

## 11. 验证与验收

默认回归必须不访问任何浏览器或测试环境，至少覆盖：

- 配置已启用 `chrome-devtools`，使用 `@latest`、隔离模式，并且没有 headless、
  remote attach 或持久 profile 参数。
- 全局默认拒绝 Chrome MCP，只有动态验证 Agent 拥有对应工具权限。
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
- 增加 XSS 以外的动态验证器。
- 将 runtime result 自动或半自动导入 adjudication、attack-chain 或 final report。
- 允许持久化测试账号配置、秘密管理集成或远程浏览器调试端口。
