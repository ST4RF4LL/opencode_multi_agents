# OpenCode 安全审计工作台架构

## 1. 目标与边界

工作台是现有 OpenCode 多 Agent 安全审计体系的本地控制面与统一交付界面。漏洞挖掘、覆盖核算、证据关联、裁决和报告封存仍由现有 Agent、Skill、MCP 与确定性校验器完成；Web 服务负责安全地创建审计运行、记录进程状态、聚合可信制品并提供一致的查询界面。

动态验证分成两层。创建任务时未启用“测试环境信息”，审计主链不会启动浏览器，所有初步支持项直接进入本地三方静态复核；启用后，主链获准执行一次、全任务最多 120 秒的 loopback 快速动态确认，未确认项仍进入三方。完整动态验证不属于普通审计的自动阶段：操作员还要启用动态 Runner，并在“完整动态验证”页面逐次明确请求、确认授权的 localhost 环境；账号及登录/清理步骤按目标实际需要选填。完整结果是 sidecar，不自动改写 routing、finding、攻击链或终稿。

## 2. 统一资源模型

工作台以 `audit_id` 为主键聚合以下资源：

- `Repository`：操作员指定的源码目录。工作台保存其规范化绝对路径、名称、Git 分支、提交和就绪状态；路径指向工作台服务所在机器，而不是浏览器所在机器。
- `Audit`：一个固定仓库与提交上的 repo 级审计运行，包括状态版本、有序事件、阶段进度、覆盖摘要、制品计数和可选 tmux 终端元数据。
- `Finding`：优先来自 correlation 阶段的 canonical finding；没有关联产物时，回退到 vulnerability-mining finding。
- `FindingWorkflow`：工作台操作员对 canonical finding 保存的独立处理状态和备注；不会修改或替代确定性 finding 制品。
- `TruthValidationBundle`：主链中的 intake、quick result、正方、反方、Moderator 与终局 routing。
- `ValidationRun`：用户手动触发的完整 localhost 动态验证结果及脱敏证据。
- `Report`：`reports/final/security-audit-report.<audit-id>.md` 的交付记录。
- `Artifact`：从 `reports/` 的受控目录扫描得到的元数据，不接受浏览器提供文件路径。

工作台把审计流水线映射为八个阶段：范围冻结、资产侦察、威胁建模、多维漏洞审计、证据关联、发现裁决、验证复核和报告封存。新任务的进度与完成状态来自 `reports/stage-deliveries/<audit-id>/` 下摘要绑定的物化阶段清单；历史无清单任务才使用带标签的制品推断。服务重启后会重新校验持久清单和文件 SHA-256，因此已完成阶段不依赖进程内存。

项目中心同时检查指定目录、Git 工作树、当前分支与提交、工作树修改以及工作台自身 OpenCode 配置的 JSON 有效性，并聚合该项目的历史/活动审计。目标源码与审计执行目录解耦：被测仓库只作为绝对源码根读取；OpenCode 在本工作台 `workspace/audit-runs/<audit-id>/` 中执行，Agent、Skill、MCP 和配置仍来自工作台安装目录，且禁用目标仓库对 Runner 配置的隐式覆盖。执行目录中的受控链接把相对 `reports/**` 与 `tmp/**` 分别导向 `reports/repositories/<repository-id>/` 和 `tmp/repositories/<repository-id>/`，所以现有制品契约不变，但不会污染被测仓库。环境中心通过 `GET /api/v1/environment` 对 Node.js、npm、Git、OpenCode、tmux/psmux、Coverage Ledger MCP、Java、Joern、OpenGrep/Semgrep、Chrome 和 Chrome DevTools MCP 生成缓存的能力快照，分别给出工作台、静态漏洞挖掘、OpenCode 窗口监控和 Web 动态验证是否可用；终端复用器或某个动态组件缺失不会错误地把静态审计标记为不可用。Windows 上只检查 Chrome 文件存在性，不执行 `chrome.exe --version`，避免环境刷新派生空白浏览器窗口。

## 3. Runner 安全模型

Runner 默认关闭。启用后从 Web 页面登记项目目录：

```sh
npm --prefix .opencode run start:audit-workbench:runner
```

工作台默认没有审计项目，也不会把自身源码作为隐式目标。操作员在“审计项目”页面输入工作台主机可访问的绝对路径；服务端对路径执行 `realpath`、目录类型和根目录范围检查，生成稳定项目 ID 并持久保存到工作台状态目录。浏览器不能通过 HTML 文件选择器取得本机绝对路径，因此这里使用明确的路径输入。`--repo service-a=/absolute/path` 作为无人值守启动时的可选预登记方式保留。若仍使用基础脚本，则必须写成 `npm --prefix .opencode run start:audit-workbench -- --enable-runner`；npm 脚本名后的参数分隔符 `--` 缺失时，开关不会传给服务进程。

创建审计时执行以下门禁：

1. `repository_id` 必须来自已持久登记的项目；创建审计时不能临时替换路径。
2. 指定目录必须存在且是 Git 工作树；审计引擎使用工作台自身有效的 `.opencode/opencode.json`。
3. 请求 ref 使用 `git rev-parse --verify` 解析，且必须等于当前 checkout 的 `HEAD`；服务不会自动 checkout。
4. 默认拒绝含未提交修改的工作树。界面可以显式选择允许脏工作树，并在运行记录中绑定实际 `HEAD`。
5. `audit_id` 使用有限字符集并全局去重；创建接口要求 `Idempotency-Key`。
6. “测试目标补充说明”与“测试环境信息”分别使用独立 ENABLE。未启用的 textarea 不进入请求；启用后必须包含非空文本。补充说明作为任务要求与侧重点，但不能扩大授权范围；测试环境开关只控制主审计中的快速动态。后续人工完整动态可在验证页补录环境和账号，并通过独立的逐次授权门禁启动。
7. Runner 创建工作台侧执行目录，并设置 `AUDIT_SOURCE_ROOT`、`AUDIT_WORKSPACE_ROOT`、`AUDIT_REPORTS_ROOT` 与 `AUDIT_TMP_ROOT`。所有源码、Git 与扫描命令必须显式使用只读源码根；所有输出只允许进入工作台侧 `reports`/`tmp` 命名空间。
8. 有 tmux/psmux 时，工作台为每个审计创建独立 `-L owa-<digest>` namespace，并在精确的 `audit:tui` 窗口直接运行 `opencode run --format json`。工作台通过任务状态目录中的只读输出中继消费同一进程的 JSONL 与退出状态，不再启动 `opencode serve`、`opencode attach` 或 loopback HTTP API。Windows 自动尝试 `tmux.exe`、`psmux.exe`、`pmux.exe`，并使用绝对 `opencode.exe` 路径。
9. OpenCode 与 multiplexer launcher 均使用参数数组和 `shell=false`；浏览器文本不会拼接为 shell 命令。tmux/psmux 不可用或 `opencode run` 能力不足时，Runner 回退到普通子进程运行同一组 `opencode run` 参数，但仍在工作台执行目录运行；静态审计仍可执行，只是没有终端监控。
10. 暂停、恢复和取消仅操作本服务持有的输出中继与该审计精确 tmux socket 中的 OpenCode run。取消已暂停任务时会先恢复精确进程组、向目标 pane 发送中断，再终止中继；不会扫描或全局终止其他 tmux、OpenCode 或浏览器进程。
11. 已结束任务可以从任务详情删除。前端只显示一次确认弹窗，不要求手工输入 `audit_id`；确认后由界面把当前选中 ID 与 `If-Match` 版本提交给服务端。运行中任务或仍有活动动态验证的任务会被拒绝。清理范围只包括工作台受控的任务状态、可归属报告、临时目录、执行工作区和关联验证/处置状态，不会删除或修改被审计源码目录。

Runner 状态和事件写入 `reports/platform/audit-runs/<audit-id>/`：

```text
run.json
additional-instructions.txt # 可选；0600
test-environment.txt        # 可选；0600，可能包含敏感测试凭证
events.jsonl
runner.log.jsonl
tmux-run.json             # tmux 模式；OpenCode run 参数和受控环境覆盖；0600
opencode-run.jsonl        # tmux 模式；实际进程输出；0600
opencode-run-exit.json    # tmux 模式；实际进程退出状态；0600
terminal-output-relay.json # tmux 模式；只读输出中继路径；0600
terminal.txt              # 任务结束时的最终只读画面（如可捕获）
```

两个 textarea 的原文不会进入 `run.json`、事件、日志、工作区快照或审计 API。`run.json` 只保存 enable、长度、固定文件名与 SHA-256；OpenCode prompt 只绑定私密文件路径与摘要，并要求 Agent 在需要时读取且不得复述秘密。Runner 从私密文件派生仅驻内存的精确脱敏词，用于日志、SSE 和 Web 返回的实时/归档终端画面。直接 attach 到本机 tmux/psmux 可以看到未经 Web 脱敏的原始 `opencode run` 输出，仍应把它视为可接触测试凭证的受信操作界面。断点恢复会重新校验文件摘要后复用原上下文；缺失或被修改时拒绝恢复。删除任务会连同该任务私密状态目录一起删除这些文件。

审计交付制品写入 `reports/repositories/<repository-id>/`，中间文件写入 `tmp/repositories/<repository-id>/`。相对路径契约仍是 `reports/final/...`、`reports/coverage/...`、`tmp/<audit-id>/...`；上述物理命名空间由执行目录链接完成。`reports/**`、`tmp/*` 和 `workspace/` 已在项目根 `.gitignore` 中忽略。动态验证 request/result 也使用同一仓库制品命名空间，不再回写测试对象目录。

## 任务中断与断点恢复

静态审计的 `run.json` 会持久化 `audit_id`、冻结提交、执行路径、OpenCode provider session id、恢复次数和事件序号。Runner 非零退出、接收到非取消类信号，或 OpenCode 以 0 退出但八环节物化校验不完整时进入 `interrupted`；工作台发现上次仍处于活动状态的任务时也会把它转换成可恢复的 `interrupted`，但不会在初始化阶段擅自终止仍可查看的精确 tmux 会话。

“断点恢复”只接受 `failed`、`interrupted` 或 `cancelled` 状态。恢复前服务端重新检查登记目录、Git 元数据、工作台 OpenCode 配置和原提交；创建任务时未允许脏工作树的，恢复时仍拒绝新增未提交修改。通过门禁后，工作台只中止并关闭该任务记录的隔离 OpenCode/tmux 目标，复用同一 `audit_id`、工作区与制品；存在 provider session id 时通过 OpenCode `--session` 续接会话，否则以现有制品作为检查点继续。恢复 prompt 要求先校验落盘制品，重建半写入或摘要不匹配的内容，并从最早未完成阶段继续。

状态文件使用临时文件加原子 rename 更新；事件按审计串行写入并具有单调递增 `sequence`。日志在持久化前执行凭证形态脱敏和单行大小限制。

## 4. 人工完整动态验证调度

动态验证需要独立的启动开关：

```sh
npm --prefix .opencode run start:audit-workbench:full -- \
  --repo application=/absolute/path/to/application
```

调度接口只接受当前仓库 `reports/validation-handoff/runtime/` 下已经通过确定性契约的密封 request 和 `P08_RUNTIME_VALIDATION.dynamic-vulnerability-validator` INPUT envelope。漏洞类型必须在目录中声明 `applies_to: web`；`JW-INJECT-06` 使用 XSS 专用强校验，其余类型使用通用 Web 契约。额外门禁如下：

1. request 所属审计必须由当前 Runner 管理。创建时未启用“测试环境信息”不阻止完整动态验证，操作员可以在当前表单补录并逐次授权。
2. 目标 URL 必须是 `http` 或 `https` 的 `localhost`、`127.0.0.1` 或 `[::1]`。
3. 操作员必须勾选显式动态验证请求和专用测试环境确认。
4. 账号与登录/清理说明可选：全部留空为匿名模式，只提供一组或同一身份为共享模式，两个不同身份才允许形成跨用户证据。
5. 当前仓库 HEAD 必须与密封 request 的 source commit 一致。
6. 已存在结果的 request 默认拒绝覆盖；同一 finding 同时最多一个动态运行。
7. 直接调用固定 `dynamic-vulnerability-validator`，该 Agent 只能使用 Chrome DevTools MCP、只能写 runtime evidence 路径，且不能调用 `agent-browser`。

动态验证表单逐次提交的结构化凭证不会写入工作台运行状态、事件或 Runner 日志；日志会同时按字段形态和本次实际账号/密码值脱敏。Runner 使用 `0600` 临时授权说明文件把当前输入交给 OpenCode，运行完成后删除该文件及任务临时目录。OpenCode session 写入本机正常 session 库并保留 provider session id，页面提供 `opencode -s <session-id>` 恢复命令；该受信本机 session 可能包含 Agent 使用测试凭证时的交互历史，因此只能使用专用测试资产。创建审计时自由填写的“测试环境信息”是另一份持久任务上下文，可能包含专用测试凭证，会按上一节所述以 `0600` 私密文件保存至任务删除。服务重启时只清理状态文件中记录且严格位于系统临时目录、名称带 `opencode-dynval-` 前缀的精确目录；不会扫描、终止或重置 Chrome/Chromium 进程。

动态验证结果读取按服务端登记仓库逐一扫描工作台侧 `reports/repositories/<repository-id>/validation-handoff/runtime/`，并为 Web 资源生成仓库作用域 ID。迁移期间可继续在受控 Windows 验证环境生成契约化、脱敏的 runtime evidence；结果同步回该工作台命名空间后，无需重新执行验证即可统一校验和展示。

## 5. API 与实时更新

主要接口：

- `GET /api/v1/workspace`：一次返回统一工作区快照。
- `GET /api/v1/repositories`：返回已登记审计项目及其规范化目录和就绪度。
- `POST /api/v1/repositories`：登记操作员指定的工作台主机绝对目录；需要 JSON、同源写请求和 `Idempotency-Key`。
- `DELETE /api/v1/repositories/:repositoryId`：移除操作员在网页登记的项目；请求体中的 `confirmation` 必须与项目 ID 完全一致。该操作不会删除源码目录或磁盘制品；项目存在关联审计时需先删除审计任务，由启动参数配置的项目不能在网页删除。
- `GET /api/v1/environment`：返回缓存的运行环境组件与能力状态；`?refresh=1` 强制重新探测。
- `GET|POST /api/v1/audits`：查询或创建审计。创建请求可包含 `additional_instructions_enabled` / `additional_instructions` 与 `test_environment_enabled` / `test_environment_context`；响应只返回 task-context enable 与长度摘要，不回显原文。
- 创建任务时的 `test_environment_context` 只决定主审计是否执行快速动态；完整动态验证允许在验证页后续补录 loopback 环境及可选账号、登录与清理说明，并逐次授权。
- `GET /api/v1/audits/{audit_id}`：返回审计快照和 `ETag`。
- `POST /api/v1/audits/{audit_id}/actions`：按 `If-Match` 版本执行暂停、进程恢复、断点恢复或取消；断点恢复使用 `{"action":"recover"}`。
- `DELETE /api/v1/audits/{audit_id}`：删除已结束任务及其工作台受控资源；前端确认弹窗自动提交与路径一致的 JSON `confirmation`，并使用 `If-Match` 防止误删已变化的任务。
- `GET /api/v1/audits/{audit_id}/events`：支持 `Last-Event-ID` 和 `after=<sequence>` 的 SSE 事件流。
- `GET /api/v1/audits/{audit_id}/terminal`：按服务端记录的精确 tmux target 返回只读实时画面或已归档的最终快照；客户端不能提交 tmux target。
- `GET /api/v1/findings`、`GET /api/v1/reports`：漏洞和报告记录。
- `POST /api/v1/findings/{resource_id}/workflow`：使用 `If-Match` 和 `Idempotency-Key` 保存人工处理状态与备注。
- `GET /api/v1/reports/{report_id}`：按服务端资源 ID 校验 SHA-256 后读取最终报告正文；浏览器不能提交文件路径。
- `GET /api/v1/reports/{report_id}/download`：下载摘要校验通过的原始 Markdown 交付件。
- `GET /api/v1/http-exchanges`：只读汇总动态验证通过 Chrome DevTools MCP 形成的脱敏 HTTP exchange，并兼容读取旧版工作台留下的历史记录；不提供主动发包或重放。
- `POST /api/v1/http-exchanges/export/bruno`：将明确选择的 1–100 条脱敏 HTTP exchange 导出为 OpenCollection ZIP，人工改包和重放完全交给 Bruno；凭据使用 `process.env` 占位符，响应只保留最小审计元数据。
- `POST /api/v1/http-exchanges/export/har`：将明确选择的 1–100 条脱敏 HTTP exchange 导出为 HAR 1.2；Cookie 数组保持为空，敏感查询参数、请求头和正文会再次脱敏。
- `GET /api/v1/validation-requests`：密封的完整动态验证请求及可调度状态。
- `POST /api/v1/validations`：在逐次完整显式授权门禁后启动隔离的完整动态验证。
- `GET /api/runs`、`GET /api/runs/{id}`：兼容动态验证证据查询。

前端会连接活动审计的 SSE 流并节流刷新统一快照，断线时仍可通过手工刷新从持久制品恢复。

Finding 人工处理状态保存在 `reports/platform/finding-workflow/`，当前支持未处理、已确认、已排除、证据不足、待动态验证、验证通过、验证失败、验证受阻和已入报告。每次修改使用乐观并发与幂等冲突检查并追加事件记录；这些状态是操作员 companion metadata，不能覆盖 canonical finding、裁决或报告模型。

报告中心区分三种完整性状态：`verified_model` 表示报告模型通过契约与自身摘要校验，且 Markdown 与确定性渲染结果逐字节一致；`digest_only` 表示历史报告仅记录本次扫描的 SHA-256，不能冒充模型绑定封存件；`model_mismatch` 表示发现模型但契约、摘要或渲染结果不一致，需要重新生成报告后再交付。

## 6. 当前部署假设

当前实现是单机、loopback、单服务进程的本地工作平台，适合个人或受控工程机。macOS 与 Linux 使用 tmux 监控；Windows 原生环境使用 psmux 的 tmux 兼容协议，WSL 仍按 Linux 形态工作。指定目录始终按工作台主机的文件系统解释：工作台运行在 Linux 服务器时，macOS 浏览器中填写的也必须是该 Linux 服务器可访问的路径。制品始终位于工作台项目所在主机，不会隐式写回被测仓库。

当前阶段建议把“统一工作台 + 静态审计 + tmux/OpenCode 会话”视为一个 Linux 主机内的高集成单元；Windows + Chrome DevTools MCP 的现有动态验证可以继续作为独立受控执行面，把契约化证据同步回对应仓库。等工作台需要真正服务团队时，再增加受认证的反向代理、OIDC/RBAC、数据库状态、签名下载和多 Runner 调度。由于当前服务仍拒绝非 loopback 监听，不能仅把它绑定到公网或局域网地址来冒充团队平台。
