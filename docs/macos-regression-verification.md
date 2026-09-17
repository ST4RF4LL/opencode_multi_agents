# macOS 可移植回归验证记录

验证日期：2026-09-17。主机：macOS 26.6.2；Node.js：v26.5.0。

用户明确授权“先验证 macOS 上可验证的部分”。本轮对 `.opencode/package.json` 主测试入口中的 23 个脚本组逐项执行，修复失败原因后复测，最终全部以退出码 0 完成。没有将模拟的 Windows/Linux 参数测试计作原生平台验收。

## 已完成的检查

下列命令均以 `npm --prefix .opencode run <脚本名>` 执行。macOS 上的运行测试和 Windows 控制器替身测试显式设置 `AUDIT_ALLOW_MACOS_PORTABLE_TESTS=1`。

| 脚本组 | 结果与范围 |
|---|---|
| `test:runtime-testing` | 31 项通过；授权跳过、租约与并发、队列取消、超时、清理、证据绑定、v3 报告门禁 |
| `test:config` | 配置一致性通过；19 个 Agent、14 个集合、52 个 Skill |
| `test:audit-todo`、`test:audit-queue` | 本地调度、工作流优化与队列通过 |
| `test:stage-agent-contract`、`test:stage-delivery-contract` | 阶段 Agent 契约 8 项、阶段交付契约 36 项通过 |
| `test:truth-validation-contract` | 旧真实性契约 23 项及共享 quick 会话回归通过 |
| `test:threat-model-contract` | 威胁模型契约 4 项通过 |
| `test:semgrep` | 使用测试扫描器验证 CLI、路径边界、SARIF、不可变运行记录与可选扫描器适配 |
| `test:finding-contract`、`test:external-runtime-validation-contract` | Finding 契约 10 项、外部运行验证交接 4 项通过 |
| `test:dynamic-validation-contract` | XSS 契约 18 项、通用 Web 验证契约 13 项通过 |
| `test:dynamic-validation-core`、`test:dynamic-validation-web` | 核心 69 项、服务 36 项通过 |
| `test:windows-control` | MOCK_ONLY 通过；使用内存 MCP 与原生接口替身，未接触原生目标 |
| `test:audit-workbench` | 快照、列表、产品目录及工作台 201 项通过 |
| `test:finding-adjudication`、`test:cvss-assessment`、`test:adjudication-regressions`、`test:attack-chain-contract` | 裁决、CVSS、语义回归、攻击链通过 |
| `test:semantic-reseed`、`test:semantic` | 来源等价约束、语义封存与覆盖通过 |
| `test:coverage` | 覆盖、5000 项规模响应、跨进程并发及冗余 I/O 回归通过 |

本轮没有只依据 `npm` 的成功退出判定 Windows 替身测试通过：已确认其输出为 `PASS / MOCK_ONLY / native_targets_contacted=false`。新增运行测试输出为 31 项通过、0 项失败、0 项跳过。

修改的 JavaScript 文件通过 `node --check`，修改的 JSON 文件可解析，`git diff --check` 通过。

## 测试暴露并修正的问题

- 阶段交付示例引用了过期的注册表摘要；更新示例绑定并重新计算示例摘要，未放宽摘要校验。
- 配置测试仍强制要求单独运行 doctor，与已经由 plan 执行健康探测的流程冲突；改为检查统一扫描入口及目标规划要求。
- 产品目录测试未考虑 macOS 的 `/var` 到 `/private/var` 规范化；预期路径改为真实路径，保留产品库的规范化行为。
- 工作台显示测试仍要求已移除的读取时完整性字段；与现有显示层契约对齐，完成时报告门禁继续由运行测试及覆盖测试验证。
- 清理断言仅等待固定次数的事件循环，可能早于文件 I/O 完成；改为有时间上限的状态等待，仍要求最终清理成功。
- 删除测试硬编码制品数量；改为核对本次审计实际拥有的制品数量，并逐个确认文件删除，同时确认无关制品保留。
- 页面仍有旧的“240/180 秒快速动态”安全边界说明；改为贯穿式参与方式、动作与总预算，并明确缺少有效环境时跳过动态。同步更新旧 UI 文案断言。

## 不在本轮验收结论内

真实 Chrome DevTools MCP 启动与关闭、真实登录和跨身份隔离、真实应用漏洞证明、实际数据清理、Windows/Linux 原生进程行为及浏览器视觉验收均未执行。没有启动真实浏览器、连接被审计目标或使用容器。

本轮证明的是 macOS 上可运行的契约、控制器替身、CLI、临时本机 HTTP 服务和工作台回归通过；不能据此宣称所有部署平台或真实动态测试已经验收。
