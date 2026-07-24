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

把存在的命令路径写入 `.opencode/opencode.json`：

```json
{
  "OPENGREP_BIN": "/absolute/path/to/opengrep",
  "SEMGREP_BIN": "/absolute/path/to/semgrep",
  "SEMGREP_ENGINE": "auto",
  "JOERN_BIN": "/absolute/path/to/joern",
  "JOERN_PARSE_BIN": "/absolute/path/to/joern-parse",
  "JOERN_VERSION": "installed-version",
  "JOERN_GNUBIN": "",
  "JOERN_JAVA_BIN": "/absolute/path/to/java/bin"
}
```

这些字段分别位于模板的 `mcp.semgrep.environment` 和 `mcp.joern.environment` 中。没有安装 Semgrep 时保留 `SEMGREP_BIN: "semgrep"` 即可；自动模式仍会使用 OpenGrep。

- `JOERN_JAVA_BIN` 填写 `dirname "$(command -v java)"` 的结果。
- Linux 通常保持 `JOERN_GNUBIN` 为空。
- macOS 安装 coreutils 后，将 `JOERN_GNUBIN` 设置为 `$(brew --prefix coreutils)/libexec/gnubin`。

`vuln_judger` 不在项目模板中定义；如需最终三方复核，请在用户全局 `~/.config/opencode/opencode.json` 中配置。OpenCode 的全局与自定义配置规则见[官方配置文档](https://opencode.ai/docs/config/)。

## 3. 验证并启动

```sh
node -e 'JSON.parse(require("node:fs").readFileSync(".opencode/opencode.json", "utf8"))'
npm --prefix .opencode test
export OPENCODE_CONFIG="$PWD/.opencode/opencode.json"
opencode
```

进入 OpenCode 后分别调用 `joern_health` 和 `semgrep_health`。两者应至少识别出 Joern、Java，以及 OpenGrep/Semgrep 中的一个；缺失项应先修正本地配置，不要在审计过程中临时跳过。
