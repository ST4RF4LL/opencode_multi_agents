# 动态验证跨平台发布验收

本清单只用于 Windows PC 与 Linux 服务器的发布验收。默认回归不会连接浏览器、不会访问目标，不能替代这里的实机证据。测试目标必须由用户显式授权，且只能是 `localhost`、`127.0.0.1` 或 `[::1]`。

验收记录使用 `DYNAMIC_VALIDATION_PLATFORM_ACCEPTANCE` v1，schema 位于 `.opencode/web/dynamic-validation-observatory/platform-acceptance.schema.json`。模板不代表通过；只有在对应操作系统上封存并通过双平台汇总校验后，才构成关闭 P2/P4 的证据。

仓库中的 `.github/workflows/dynamic-validation-platform-contract.yml` 会在 `windows-latest` 与 `ubuntu-latest` 运行无浏览器契约回归。CI 证明 Node.js、CLI 和文件路径代码可以在两个 OS 上执行，但不拥有桌面会话、用户 Chrome 或 Bruno Desktop，因此不能替代 P2/P4 实机验收。

发布产物和实机验收都必须直接运行在目标 Windows/Linux 主机上。不得通过 Docker、Podman、Compose、容器镜像或容器内 Chrome 完成任何步骤；CI 使用 GitHub 托管的普通 Windows/Ubuntu runner，不构建或运行容器。

## 前置检查

在目标机器的仓库根目录执行：

```sh
npm ci --prefix .opencode
npm --prefix .opencode run test:dynamic-validation-contract
npm --prefix .opencode run test:dynamic-validation-core
npm --prefix .opencode run test:dynamic-validation-web
npm --prefix .opencode run dynval:doctor
```

保存命令输出、操作系统版本、CPU 架构、Node.js 版本、Chrome 完整版本、Chrome DevTools MCP 实际版本和 Bruno Desktop 完整版本。不得在证据中记录凭据、Cookie、token 或真实用户数据。

在 Windows 和 Linux 上分别生成模板：

```sh
npm --prefix .opencode run dynval -- acceptance template --platform windows --output windows-acceptance.json
npm --prefix .opencode run dynval -- acceptance template --platform linux --output linux-acceptance.json
```

只执行当前机器对应的一条命令。完成下述人工步骤后填写版本、布尔判定与脱敏证据文件 SHA-256，再在同一目标机器封存：

```sh
npm --prefix .opencode run dynval -- acceptance seal --input windows-acceptance.json --output windows-acceptance.sealed.json
npm --prefix .opencode run dynval -- acceptance seal --input linux-acceptance.json --output linux-acceptance.sealed.json
```

`seal` 会拒绝当前 OS 与记录平台不一致、Chrome 低于 144、MCP 不是 1.8.0、Bruno Desktop 低于 4、目标不是显式授权 loopback、P2/P4 任一检查未通过、使用过全局 Chrome 终止、使用过 Docker/Podman 等容器运行时、清理失败、缺少证据摘要或疑似包含认证值的记录。

## P2：Browser Session Broker

### Windows PC

1. 使用 Chrome 144+ 的专用测试 profile，开启远程调试，并确认“控制器可见该 profile 的其他页面”提示。
2. 在没有隔离风险信号的测试任务中选择 `shared_tab`。验证只创建一个新标签页；预先存在的页面不被导航、读取或关闭。
3. 结束任务。验证新建标签页被关闭，预先存在的 Chrome 窗口、页面、登录态保持不变。
4. 使用带 `distinct_accounts` 或 `stored_xss` 风险的任务。验证 Broker 自动选择 `isolated_browser`，而不是共享标签页。
5. 结束任务。验证隔离实例关闭，共享 Chrome 仍保持运行。禁止用 `taskkill`、`Stop-Process` 或任何全局 Chrome 终止命令完成验收。

### Linux 服务器

1. 有桌面环境时重复 Windows 的共享标签页与隔离实例检查。
2. 无 `DISPLAY`/`WAYLAND_DISPLAY` 时运行隔离测试任务，验证 MCP 参数包含 `--isolated=true` 与 `--headless=true`。
3. 结束任务后验证受管隔离实例退出，服务器上其他 Chrome/Chromium 进程（如存在）不受影响。禁止使用 `pkill`、`killall` 或通配 PID 清理。

每个平台的通过证据至少包括：Broker 会话 ID/模式、任务创建 page/context 清单、清理前后受管资源状态，以及预存页面未变化的人工确认。凭据和页面敏感内容必须脱敏。

## P4：Bruno 4 Desktop

1. 在请求工作台构造一个不含秘密的 loopback 测试请求，并生成成功记录；再生成一条修改后重发记录。
2. 勾选两条记录，导出 OpenCollection ZIP。解压后确认存在 `opencollection.yml`、`environments/local.yml`、`requests/*.yml`、`.env.example` 与中文 `README.md`。
3. 使用 Bruno 4 Desktop 打开解压目录，选择 `local` 环境。确认方法、路径、重复查询参数、普通请求头和请求体保持一致。
4. 若请求包含已脱敏认证字段，仅在本机 `.env` 临时补值；确认集合文件和 `.env.example` 中没有实际秘密。
5. 在仍为授权 loopback 环境的前提下运行两条请求，确认响应符合测试服务预期。完成后删除临时 `.env`。

Windows 与 Linux 必须分别保存：Bruno 版本、打开集合后的请求清单截图、环境变量名称清单（无值）、运行摘要和临时 `.env` 已删除的确认。任何截图都不得包含凭据或无关数据。

## 通过判定

- 两个平台的所有步骤均通过，才可勾选 `TODO.md` 的 P2 与 P4。
- 任一清理步骤失败时不得通过 P2；应记录仍存活的精确受管资源并人工处理，不能转用全局进程终止。
- OpenCollection 需要手工编辑集合结构、秘密落盘或请求语义发生变化时不得通过 P4。
- 缺少授权 loopback 环境时，本验收记为 `SKIPPED`，不得为了完成发布门禁而自行启动浏览器或联系目标。

收集两个平台的封存件后执行最终汇总：

```sh
npm --prefix .opencode run dynval -- acceptance verify \
  --windows windows-acceptance.sealed.json \
  --linux linux-acceptance.sealed.json \
  --output dynamic-validation-acceptance-matrix.json
```

只有输出 `status: PASS` 才能勾选 P2/P4。`BLOCKED` 使用退出码 2；schema、摘要或检查项错误会逐项输出机器可读问题路径。
