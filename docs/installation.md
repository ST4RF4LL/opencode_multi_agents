# 初始化与安装

首次使用只需完成三件事：安装运行时与扫描器、生成本地配置、执行健康检查。

## 1. 安装基础组件

需要：

- Git、Node.js 20+ 与 npm。
- OpenCode。可按[官方安装说明](https://opencode.ai/docs/)执行：

  ```sh
  curl -fsSL https://opencode.ai/install | bash
  ```

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

`vuln_judger` 不在项目模板中定义；如需最终三方复核，请在用户全局 `~/.config/opencode/opencode.json` 中配置。OpenCode 的全局与自定义配置规则见[官方配置文档](https://opencode.ai/docs/config/)。

## 3. 验证并启动

```sh
./initial.sh
export OPENCODE_CONFIG="$PWD/.opencode/opencode.json"
opencode
```

`initial.sh` 会直接解析并检查 OpenGrep/Semgrep、`joern`、`joern-parse`、Java 及可选 GNU coreutils，同时检查核心 CLI、项目依赖、本地和全局 OpenCode 配置，以及 Coverage Ledger MCP 的实际健康状态。OpenGrep 与 Semgrep 合并为一个扫描器检查项：自动模式下二选一即可，优先使用 OpenGrep。它默认不运行完整回归，也不执行语言 CPG 构建。

```sh
./initial.sh --python          # Python 项目：额外验证 Joern Python 前端
./initial.sh --require-review  # 要求全局已配置 vuln_judger
./initial.sh --test            # 初始化检查通过后执行完整回归
```

输出中的 `【通过】` 表示当前工作流可用，`【警告】` 表示可选能力缺失，`【失败】` 表示所选工作流被阻断。处理完 `【失败】` 后重新运行 `./initial.sh`；只有 Python 审计、最终三方复核或完整回归需要时，才分别增加对应参数。

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
