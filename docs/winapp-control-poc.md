# winappCli 控制层第一阶段

## 当前交付

`dev` 已加入可供原生 Windows 验收的 winappCli 0.6.0 控制层源码：

| 文件 | 功能 |
| --- | --- |
| [windows-control-core.mjs](../.opencode/scripts/windows-control-core.mjs) | 授权快照、命令编译、会话状态、输出过滤、清理 |
| [windows-control-native.mjs](../.opencode/scripts/windows-control-native.mjs) | 固定 argv 调用、文件摘要、桌面租约、原生身份检查 |
| [windows-control-guard.ps1](../.opencode/scripts/windows-control-guard.ps1) | 检查 PID/创建时间/EXE/HWND/Windows session、UIA 控件和密码属性 |
| [windows-control-cli.mjs](../.opencode/scripts/windows-control-cli.mjs) | `plan` 静态检查与 `run` 控制探针入口 |
| [windows-control-mcp.mjs](../.opencode/scripts/windows-control-mcp.mjs) | 同一控制层的 stdio MCP；工具列表与状态读取不接触目标 |
| [WinappControlFixture.csproj](../.opencode/tests/fixtures/winapp-control/WinappControlFixture.csproj) | 无网络/文件访问的内存测试应用源码 |
| [run-windows-control-tests.mjs](../.opencode/tests/run-windows-control-tests.mjs) | 模拟控制与内存 MCP 回归，不启动 Windows 应用或浏览器 |

调用链已落实为 `CLI / MCP → WindowsControlSession → winapp.exe ui → 指定测试控件`。
项目配置已登记 `windows-control` MCP，但 `enabled=false`，全局工具权限为 deny。
完整动态验证 Agent 目前只可读取 winapp Skill；P08、Web 表单和调度仍未开放桌面执行。

当前工作区为 macOS，已完成 JavaScript 语法及配置/文档静态核对；Windows/Linux
模拟回归、PowerShell 原生检查和 WPF 编译/运行尚未在对应宿主机验收。真实动态验证
为 `SKIPPED`，没有安装 winappCli、构建/启动 fixture、打开浏览器或接触测试目标。

## 首期范围

只接受用户明确授权的、同机同 Windows session、无真实数据的离线测试实例。首期
仅附加既有实例，不启动/结束目标进程；不提供应用枚举、模糊 selector、坐标、键盘、
截图、录像、文件/注册表/网络采集。固定 AutomationId 需要由测试应用或操作者提供。
WPF fixture 已为四个控件提供唯一 AutomationId。

`set_value` 只写控制器生成的唯一 `audit-winapp-…` 字符串，工具不接受任意文本。
`get_state` 仅返回 marker 是否出现，不返回 UI 原始值、标题或错误文本。`inspect`
仅返回登记控件存在/启用状态。直接 InvokePattern 之外的动作一律拒绝。
两次原生身份核对之间仍存在操作系统竞态窗口，因此该版本只适合专用离线 fixture，
尚未达到对任意不可信桌面程序进行漏洞验证的隔离强度。

## 在授权 Windows 测试机上准备

以下步骤供之后用户明确启用本机 Windows fixture 验收时使用，不会由安装或 CI
自动执行。需要原生 Windows 交互桌面、.NET 8 SDK 和微软 winappCli v0.6.0。
从 [v0.6.0 发布页](https://github.com/microsoft/winappCli/releases/tag/v0.6.0) 获取对应
架构的独立 ZIP 并核验可信来源，将 winapp.exe 放在本机固定磁盘目录；不自动下载
开发分支、SDK 或证书。SHA-256 绑定用于发现变更，不能代替来源可信性检查。

在仓库根目录逐步执行：

```powershell
dotnet build .opencode/tests/fixtures/winapp-control/WinappControlFixture.csproj -c Release
```

随后手动启动生成的测试 EXE，记录该实例的 PID。保持专用测试会话解锁，确认测试
程序未被改成访问外部服务。下面的 `1234` 和 winapp 路径需要替换成已授权实例信息；
代码只读取指定进程，不搜索其他应用。不要使用真实业务程序/真实账号生成该配置。

```powershell
$fixtureProcess = Get-Process -Id 1234
$fixtureProcess.Refresh()
$winappPath = 'C:\Tools\winapp\winapp.exe'
$fixtureExe = $fixtureProcess.MainModule.FileName
$controlSpec = @{
  schema_version = 1
  task_id = 'winapp-fixture-probe'
  authorization = @{
    explicit_authorization = $true
    test_environment = $true
    synthetic_data_only = $true
    network_mode = 'offline_fixture'
    account_mode = 'anonymous'
    expires_at = [DateTime]::UtcNow.AddMinutes(20).ToString('o')
  }
  tool = @{
    path = $winappPath
    sha256 = (Get-FileHash -LiteralPath $winappPath -Algorithm SHA256).Hash.ToLowerInvariant()
    version = '0.6.0'
  }
  target = @{
    exe_path = $fixtureExe
    exe_sha256 = (Get-FileHash -LiteralPath $fixtureExe -Algorithm SHA256).Hash.ToLowerInvariant()
    pid = $fixtureProcess.Id
    start_time_ticks = $fixtureProcess.StartTime.ToUniversalTime().Ticks.ToString()
    hwnd = $fixtureProcess.MainWindowHandle.ToInt64().ToString()
    windows_session_id = $fixtureProcess.SessionId
  }
  controls = @(
    @{ id = 'input'; automation_id = 'MarkerInput'; actions = @('inspect', 'set_value') }
    @{ id = 'submit'; automation_id = 'SubmitMarker'; actions = @('invoke') }
    @{ id = 'status'; automation_id = 'MarkerStatus'; actions = @('get_state', 'wait_for') }
    @{ id = 'clear'; automation_id = 'ClearMarker'; actions = @('invoke') }
  )
  cleanup = @{ invoke_control_id = 'clear'; verify_control_id = 'status' }
}
$specPath = Join-Path $env:TEMP 'winapp-fixture-control.json'
[IO.File]::WriteAllText($specPath, ($controlSpec | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
```

配置绑定的是当前进程实例；重启应用后需要重新生成，不能复用旧 PID/HWND。
控制器检查路径、磁盘类型和摘要，拒绝网络盘、UNC、备用数据流及重解析路径。
当前版本只接受本机 `SystemRoot=C:\Windows`（或其他盘符同名目录）的原生系统。
PowerShell 执行策略若禁止运行项目脚本，控制器会停止；不会自动修改执行策略。

## 独立 CLI 试用

先检查配置和步骤：

```powershell
node .opencode/scripts/windows-control-cli.mjs plan --spec $specPath --plan .opencode/tests/fixtures/winapp-control/control-plan.json
```

预期为 `PLAN_VALID`，同时明确 `structural_only=true`、`execution_authorized=false`。
这一操作只解析文件，不探测 EXE/桌面，不代表进程身份已验收。

在已显式授权的 Windows fixture 环境执行：

```powershell
node .opencode/scripts/windows-control-cli.mjs run --enable-winapp-control --spec $specPath --plan .opencode/tests/fixtures/winapp-control/control-plan.json
```

预期步骤为观察输入框 → 写 marker → 点击提交 → 等待结果 → 核对 marker → 自动清理。
结果包含 `CONTROL_PROBE_ONLY`、`vulnerability_confirmed=false`、各步骤状态和清理状态。
CLI 成功仅说明控制探针完成；不会生成 P08 `SUPPORTED_RUNTIME` 结果。

缺少开关、Windows 宿主机、有效授权、离线测试声明或所需预登录状态时返回
`SKIPPED`，不调用任何原生控制进程。账号模式只支持匿名和事先登录的专用测试会话，
不接收用户名/密码。部署安全边界仍以根 `AGENTS.md` 和当前用户授权为准。

## MCP 入口

供后续独立验收客户端连接的启动命令：

```powershell
node .opencode/scripts/windows-control-mcp.mjs --enable-winapp-control --spec $specPath
```

它通过 stdio 通信，不开 HTTP 监听。一个进程只绑定一份授权配置；工具输入只接受
`control_id`，不能换 spec、EXE、PID、HWND、输出路径或凭证。工具有 `status`、
`inspect`、`set_value`、`invoke`、`get_state`、`wait_for`、`cleanup`、`close`。
首次控制动作才获取租约；`tools/list` 和 `status` 不接触桌面。

MCP 与 CLI 共享门禁和清理规则。当前项目 Agent 没有 Windows MCP 权限，因此不会
通过现有审计流程自动启动它。Agent 权限接入应与 P08 桌面契约一起实施。

## 故障与清理

每个 CLI 调用最多 8 秒、输出最多 1 MiB；会话最多 50 个用户步骤、5 分钟，清理另有
有界调用预算。控件过期、密码控件、会话/窗口漂移、程序摘要变化和异常 CLI 输出会
停止后续用户动作。已经可能产生副作用的步骤失败后，仍尝试授权的固定清理路径；
授权已过期或身份无法确认时，清理也不执行越界动作，记录失败交由人工处理。

清理失败或控制器崩溃留下桌面租约，避免新任务覆盖残留状态。租约位于同一 Windows
用户临时目录的 `opencode-winapp-desktop-leases-v1/session-<session_id>.lock`，记录
控制器 PID、task ID 和 binding digest。先在授权应用内核对/清理 marker，确认原控制器
已经退出后，操作者才可删除该**精确租约文件**。不自动抢占或清除“过期”租约。

正常 MCP 断开会等待正在执行的有界动作结束，再尝试清理；强制终止不能保证回调运行，
以残留租约要求人工恢复。当前 CLI 没有平台级取消/恢复调度，这属于下一阶段。
清理复核仅针对 spec 指定的观察控件，不能证明任意业务应用的全部持久状态已删除。

## 验证与下一阶段

原生 Windows/Linux 回归命令：

```text
npm --prefix .opencode run test:windows-control
```

模拟测试使用假的 native adapter、假的 exec 回调和内存 MCP 连接；只在临时测试目录
检查租约，不启动浏览器、winapp.exe、PowerShell 或 fixture。已加入现有 Windows/Linux
CI 矩阵，未推送/未运行的 CI 不应记录为通过。fixture 编译和真实动态操作需另行显式授权。

下一阶段是 P08 桌面 target/result schema、Agent 最小权限和后端路由；再接入 Web
表单、调度队列与证据页。截图与文件/网络影响采集要分别实现范围和脱敏约束后开放。
