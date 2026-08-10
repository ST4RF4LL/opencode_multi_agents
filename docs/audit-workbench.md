# OpenCode 安全审计工作台架构

## 1. 目标与边界

工作台是现有 OpenCode 多 Agent 安全审计体系的本地控制面与统一交付界面。漏洞挖掘、覆盖核算、证据关联、裁决和报告封存仍由现有 Agent、Skill、MCP 与确定性校验器完成；Web 服务负责安全地创建审计运行、记录进程状态、聚合可信制品并提供一致的查询界面。

动态漏洞验证不属于普通审计任务的自动阶段。即使静态发现生成了 runtime-validation request，工作台也不会据此启动验证。只有操作员额外启用动态 Runner，并在动态验证表单中逐次明确请求、确认授权的 localhost 环境、提供两个不同测试账号及登录/清理步骤后，工作台才会调度动态验证 Agent。

## 2. 统一资源模型

工作台以 `audit_id` 为主键聚合以下资源：

- `Repository`：服务端白名单中的 Git 仓库，只向浏览器暴露 ID、名称、分支、提交和就绪状态，不返回绝对路径。
- `Audit`：一个固定仓库与提交上的 repo 级审计运行，包括状态版本、有序事件、阶段进度、覆盖摘要和制品计数。
- `Finding`：优先来自 correlation 阶段的 canonical finding；没有关联产物时，回退到 vulnerability-mining finding。
- `ValidationRun`：已完成的授权 localhost 动态验证结果及脱敏证据。
- `Report`：`reports/final/security-audit-report.<audit-id>.md` 的交付记录。
- `Artifact`：从 `reports/` 的受控目录扫描得到的元数据，不接受浏览器提供文件路径。

工作台把审计流水线映射为八个阶段：范围冻结、资产侦察、威胁建模、多维漏洞审计、证据关联、发现裁决、验证复核和报告封存。服务重启后会再次扫描持久制品，因此已完成阶段不依赖进程内存。

## 3. Runner 安全模型

Runner 默认关闭。启用方式：

```sh
npm --prefix .opencode run start:audit-workbench -- \
  --enable-runner \
  --repo service-a=/absolute/path/to/service-a
```

创建审计时执行以下门禁：

1. `repository_id` 必须来自服务端启动参数，浏览器不能提供路径。
2. 仓库必须是 Git 工作树，并包含 `.opencode/opencode.json`。
3. 请求 ref 使用 `git rev-parse --verify` 解析，且必须等于当前 checkout 的 `HEAD`；服务不会自动 checkout。
4. 默认拒绝含未提交修改的工作树。界面可以显式选择允许脏工作树，并在运行记录中绑定实际 `HEAD`。
5. `audit_id` 使用有限字符集并全局去重；创建接口要求 `Idempotency-Key`。
6. OpenCode 使用参数数组、`shell=false`、固定 `security-audit-orchestrator` 和服务端 prompt 启动，浏览器文本不会拼接为 shell 命令。
7. 暂停、恢复和取消仅向本服务持有的子进程发送 `SIGSTOP`、`SIGCONT` 或 `SIGTERM`，不会执行全局进程终止。

Runner 状态和事件写入 `reports/platform/audit-runs/<audit-id>/`：

```text
run.json
events.jsonl
runner.log.jsonl
```

状态文件使用临时文件加原子 rename 更新；事件按审计串行写入并具有单调递增 `sequence`。日志在持久化前执行凭证形态脱敏和单行大小限制。

## 4. 动态验证调度

动态验证需要独立的启动开关：

```sh
npm --prefix .opencode run start:audit-workbench -- \
  --enable-dynamic-validation \
  --repo application=/absolute/path/to/application
```

调度接口只接受当前仓库 `reports/validation-handoff/runtime/` 下已经通过确定性契约的密封 request 和 `P08_RUNTIME_VALIDATION.dynamic-vulnerability-validator` INPUT envelope。当前只接受 `JW-INJECT-06`，并执行以下额外门禁：

1. 目标 URL 必须是 `http` 或 `https` 的 `localhost`、`127.0.0.1` 或 `[::1]`。
2. 操作员必须勾选显式动态验证请求和专用测试环境确认。
3. Attacker 与 victim 账号必须不同；用户名、密码、登录说明和清理说明均为本次请求必填。
4. 当前仓库 HEAD 必须与密封 request 的 source commit 一致。
5. 已存在结果的 request 默认拒绝覆盖；同一 finding 同时最多一个动态运行。
6. 直接调用固定 `dynamic-vulnerability-validator`，该 Agent 只能使用 Chrome DevTools MCP、只能写 runtime evidence 路径，且不能调用 `agent-browser`。

凭证不会写入工作台运行状态、事件或日志。动态 Runner 为每次调用创建独立 `XDG_DATA_HOME` / `XDG_STATE_HOME`，仅复制 OpenCode 运行所需的本机认证文件；用户输入只存在于该临时会话。日志会同时按字段形态和本次实际账号/密码值脱敏。运行完成后删除整个临时会话目录并记录清理状态。服务重启时只清理状态文件中记录且严格位于系统临时目录、名称带 `opencode-dynval-` 前缀的精确目录；不会扫描、终止或重置 Chrome/Chromium 进程。

## 5. API 与实时更新

主要接口：

- `GET /api/v1/workspace`：一次返回统一工作区快照。
- `GET /api/v1/repositories`：返回白名单仓库的安全摘要。
- `GET|POST /api/v1/audits`：查询或创建审计。
- `GET /api/v1/audits/{audit_id}`：返回审计快照和 `ETag`。
- `POST /api/v1/audits/{audit_id}/actions`：按 `If-Match` 版本执行暂停、恢复或取消。
- `GET /api/v1/audits/{audit_id}/events`：支持 `Last-Event-ID` 和 `after=<sequence>` 的 SSE 事件流。
- `GET /api/v1/findings`、`GET /api/v1/reports`：漏洞和报告记录。
- `GET /api/v1/validation-requests`：密封动态验证请求及可调度状态。
- `POST /api/v1/validations`：在完整显式授权门禁后启动隔离动态验证。
- `GET /api/runs`、`GET /api/runs/{id}`：兼容动态验证证据查询。

前端会连接活动审计的 SSE 流并节流刷新统一快照，断线时仍可通过手工刷新从持久制品恢复。

## 6. 当前部署假设

当前实现是单机、loopback、单服务进程的本地工作平台，适合个人或受控工程机。它拒绝监听非 loopback 地址，因此没有内建远程用户认证。若未来扩展为团队服务，需要在保持仓库白名单、幂等、乐观并发、制品路径约束和日志脱敏的前提下增加 OIDC/RBAC、数据库状态、签名下载与多 Runner 调度。
