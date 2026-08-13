# 初始化与安装

首次使用只需完成三件事：安装运行时与扫描器、生成本地配置、执行健康检查。

## 1. 安装基础组件

需要：

- Git、Node.js 20+ 与 npm。
- 当前稳定版 Google Chrome。动态 Web-XSS 验证会启动一个可见的隔离 Chrome；不会连接日常浏览器 profile。
- OpenCode。可按[官方安装说明](https://opencode.ai/docs/)执行：

  ```sh
  curl -fsSL https://opencode.ai/install | bash
  ```

- 终端复用器（推荐）。macOS/Linux/WSL 使用 tmux；Windows 原生环境使用 psmux（支持 tmux CLI 协议）。它用于工作台中的只读 OpenCode 实时窗口；缺失时静态审计仍会回退到普通 Runner。macOS 可执行 `brew install tmux`，Debian/Ubuntu/WSL 可执行 `sudo apt install tmux`；Windows 安装 psmux，并确保 `psmux.exe`（或它提供的 `tmux.exe` 别名）位于 PATH。

- JDK 与 Joern。Joern 官方文档以 JDK 19 为前提；如使用更新 JDK，请在本机验证兼容性。按[Joern 安装说明](https://docs.joern.io/installation/)安装最新预编译版本：

  ```sh
  curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o joern-install.sh
  chmod u+x joern-install.sh
  ./joern-install.sh --interactive
  ```

  macOS 若缺少 `greadlink`，额外执行：

  ```sh
  brew install coreutils
  ```

- OpenGrep 或 Semgrep，至少安装一个。默认优先 OpenGrep，找不到时回退 Semgrep。

  OpenGrep 的[官方快速安装](https://github.com/opengrep/opengrep)：

  ```sh
  curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
  ```

  可选的 Semgrep 回退，按[Semgrep 官方说明](https://semgrep.dev/docs/category/local-and-cli-scans)使用 `pipx`：

  ```sh
  pipx install semgrep
  ```

安装项目内的 Node.js 依赖：

```sh
npm ci --prefix .opencode
```

## 2. 生成本地配置

复制无本机路径的模板：

```sh
cp .opencode/opencode.json.bak .opencode/opencode.json
```

`.opencode/opencode.json` 已被 Git 忽略，不会提交本机安装目录。先取得实际路径：

```sh
command -v joern
command -v joern-parse
command -v java
command -v opengrep
command -v semgrep
```

Semgrep/OpenGrep 不再通过项目 MCP 配置。若命令已在 `PATH` 中无需额外设置；否则在运行 `initial.sh`、受控扫描 CLI 和 OpenCode 的同一个 Shell 中导出：

```sh
export OPENGREP_BIN="/absolute/path/to/opengrep"
export SEMGREP_BIN="/absolute/path/to/semgrep"
export SEMGREP_ENGINE="auto"
```

没有安装 Semgrep 时可不设置 `SEMGREP_BIN`；自动模式仍会使用 OpenGrep。反之亦然。

Joern 不再通过项目 MCP 配置。只要 `joern`、`joern-parse` 和 `java` 已在 `PATH` 中，就不需要额外配置；否则在启动 `initial.sh` 和 OpenCode 的同一个 Shell 中导出：

```sh
export JOERN_BIN="/absolute/path/to/joern"
export JOERN_PARSE_BIN="/absolute/path/to/joern-parse"
export JOERN_JAVA_BIN="/absolute/path/to/java/bin"
export JOERN_GNUBIN=""
```

- `JOERN_JAVA_BIN` 填写 `dirname "$(command -v java)"` 的结果。
- Linux 通常保持 `JOERN_GNUBIN` 为空。
- macOS 安装 coreutils 后，将 `JOERN_GNUBIN` 设置为 `$(brew --prefix coreutils)/libexec/gnubin`。
- 如需长期使用，将这些导出写入你的 Shell 配置或专用启动脚本；不要再创建 `mcp.joern` 配置。

finding 真实性复核由项目内 `vulnerability-affirmative`、`vulnerability-negative`、`vulnerability-moderator` 三个独立 OpenCode session 完成，不需要额外 Python 服务、Web UI 或全局 review MCP。

项目模板已配置 `npx -y chrome-devtools-mcp@latest --isolated=true`。它只暴露给快速动态和人工完整动态两个验证 Agent，并且仅在调用浏览器工具时启动可见 Chrome，因此首次动态验证需要 npm 网络访问或已有 npx 缓存。不要添加 `--headless`、`--autoConnect`、`--browser-url`、持久化 `--user-data-dir` 或 `agent-browser` 回退。当前目标只允许 `localhost`、`127.0.0.1` 和 `[::1]`。

## 3. 验证并启动

```sh
./initial.sh
export OPENCODE_CONFIG="$PWD/.opencode/opencode.json"
opencode
```

需要统一查看审计任务、漏洞、报告和已生成的动态验证证据时，另开一个终端启动只读工作台：

```sh
npm --prefix .opencode run start:audit-workbench
```

然后访问 `http://127.0.0.1:4173`。服务只允许监听 loopback 地址。默认不会启动 OpenCode，也不会执行新的动态验证。

允许通过 Web 创建静态审计任务时，启动 Runner，然后在“审计项目”页面指定工作台所在机器上的源码绝对目录。目标目录不需要包含 `.opencode/opencode.json`；工作台使用自身已生成的配置，并默认要求目标是干净的 Git 工作树：

```sh
npm --prefix .opencode run start:audit-workbench:runner
```

当 tmux/psmux 与当前 OpenCode 的 `attach --dir`、`--session`、`--mini` 能力就绪时，新任务详情会显示“监控 OpenCode”。网页只读捕获工作台创建的精确 `audit:tui` 窗口；也可复制页面给出的 `tmux -L ...` 或 `psmux -L ...` 命令，在工作台主机以只读 client 直接查看。Windows 会优先解析 `opencode.exe`，必要时可用 `OPENCODE_BIN_PATH` 指向其绝对路径。任务完成后精确 multiplexer server 会关闭，最后一屏保存为只读快照。已经在旧版本中启动的任务不会被热迁移，需在重启工作台后新建任务才能获得该窗口。

新任务不会再向指定的测试对象目录写入 `reports/` 或 `tmp/`。静态与动态 Runner 都在本项目 `workspace/audit-runs/<audit-id>/` 下执行；持久制品按仓库隔离到 `reports/repositories/<repository-id>/`，中间文件隔离到 `tmp/repositories/<repository-id>/`。这三类目录已由项目根 `.gitignore` 忽略。升级前已经启动的任务仍按旧进程的目录规则运行，工作台不会在任务执行期间移动其文件；待旧任务结束并重启工作台后，新建任务才使用隔离路径。

需要在自动化启动时预登记目录，仍可使用一个或多个 `--repo id=/absolute/path`：

```sh
npm --prefix .opencode run start:audit-workbench:runner -- \
  --repo application=/absolute/path/to/application
```

工作台不会因为省略 `--repo` 就审计自身；此时项目列表为空，等待操作员指定目录。使用基础启动脚本自行传递开关时，必须在 npm 脚本名后加入参数分隔符：`npm --prefix .opencode run start:audit-workbench -- --enable-runner`。缺少中间的 `--` 时，npm 会把 `--enable-runner` 当成自身配置，服务端实际上收不到该开关。

创建审计时，“测试目标补充说明”和“测试环境信息”可以分别 ENABLE；前者只调整任务要求和侧重点。未启用测试环境时，主链不会启动浏览器，所有初步支持项直接进入本地三方静态复核。启用测试环境即授权主链执行一次、全任务最多 120 秒的 loopback 快速动态确认；未确认、超时或受阻的项目仍转入静态三方。创建任务时的自由格式环境上下文会以 `0600` 私密文件保存到任务删除，只应填写专用测试凭证。

完整动态验证始终不自动运行。需要通过 Web 手动触发时，使用 `npm --prefix .opencode run start:audit-workbench:full`，或在基础命令的 `--` 后同时加入 `--enable-runner --enable-dynamic-validation`。操作员仍需在“完整动态验证”页面选择一条密封且待处理的 XSS request，并逐次填写 loopback URL、两个不同测试账号、登录步骤和清理步骤；结果作为 sidecar，不自动改写主链 routing 或终稿。

`initial.sh` 会直接解析并检查 OpenGrep/Semgrep、`joern`、`joern-parse`、Java 及可选 GNU coreutils，同时检查核心 CLI、项目依赖、本地和全局 OpenCode 配置，以及 Coverage Ledger MCP 的实际健康状态。OpenGrep 与 Semgrep 合并为一个扫描器检查项：自动模式下二选一即可，优先使用 OpenGrep。它默认不运行完整回归，也不执行语言 CPG 构建。

工作台启动后还可以在“运行环境”页面查看同一组组件的在线能力快照。该页面分别计算工作台、静态漏洞挖掘、OpenCode 窗口监控和 Web 动态验证就绪度；点击“重新探测”会绕过 30 秒缓存，但不会启动 Chrome、执行扫描或发起动态验证。

```sh
./initial.sh --python          # Python 项目：额外验证 Joern Python 前端
./initial.sh --test            # 初始化检查通过后执行完整回归
```

输出中的 `【通过】` 表示当前工作流可用，`【警告】` 表示可选能力缺失，`【失败】` 表示所选工作流被阻断。处理完 `【失败】` 后重新运行 `./initial.sh`；只有 Python 前端冒烟检查或完整回归需要时，才分别增加对应参数。

Joern 和 OpenGrep/Semgrep 的可用性都由 `initial.sh` 直接检查。也可运行：

```sh
node .opencode/scripts/semgrep-scan.mjs health
node .opencode/scripts/semgrep-scan.mjs scan \
  --audit-id audit-001 \
  --session-id web-r1 \
  --agent-name java-source-auditor \
  --target src \
  --rule .opencode/skills/java-subagent/java-sql-injection/rules/semgrep/java-sqli-sinks.yaml
```

`scan` 只接受工作区内的本地规则和目标，完整 JSON、stderr 与 SARIF 落盘，终端只返回有硬上限的 JSON 摘要。工具缺失时应修正当前 Shell 的 `PATH` 或上述环境变量，不要在审计过程中临时跳过。
