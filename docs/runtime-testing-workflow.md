# 贯穿式运行测试

新建任务现在可以选择“环境接触 + 中期探索 + 按需确认”“仅环境接触”或“环境接触 + 定向确认”。前期正常环境接触与 Recon 并行；中期按 Focus Area 假设执行测试，有源码候选后立即按需确认；收尾只封存证据、完成必要清理和独立三方复核，不再追加固定 180 秒批次。

## 使用方式

在新建审计窗口启用“测试环境信息”，选择参与方式、身份和允许的动作，并填写环境。未启用、未填写、地址非法、账号不足，全部动态环节自动 SKIPPED，静态审计继续，不要求补录、不暂停、不启动浏览器。原 API 未发送 runtime_testing 选择的客户端仍使用旧协议；旧任务恢复时也不会自动扩展授权。

匿名环境可直接填写 `URL: http://127.0.0.1:8080`。需要登录时必须选择对应身份模式，填写测试账号。多身份或持久化测试使用 JSON，例如：

```json
{
  "url": "http://127.0.0.1:8080",
  "revision": "test-deployment-2026-09-15",
  "source_revision": "<可选：声明对应的源码提交>",
  "accounts": [
    { "id": "attacker", "username": "<授权测试账号一>", "password": "<测试密码>", "role": "test-user" },
    { "id": "victim", "username": "<授权测试账号二>", "password": "<测试密码>", "role": "test-user" }
  ],
  "login_instructions": "通过应用登录入口登录，仅操作测试数据。",
  "test_data_scope": "两份指定的测试资料记录",
  "cleanup_instructions": "通过应用编辑入口恢复测试资料，重访确认标记消失。"
}
```

勾选“创建并清理测试记录”时，测试数据范围和清理说明也是必要信息。工作包不能自行扩大这份数据范围。只有显式提供的 origin 被授权，其他端口、外部跳转和外部子资源均被代理拒绝。不同测试身份使用独立 Chrome DevTools MCP 浏览器，禁止接管用户已有 Chrome。

## 结果与预算

工作台任务详情展示 CONTACT、EXPLORE、CONFIRM、CLEANUP 的状态、每包结果、耗时与清理状态。执行成功并不代表漏洞成立；SUPPORTED 是工作包的观察标签，必须经过独立正方、反方与 Moderator 复核。

默认总预算 60 分钟，其中 10 分钟留给清理；单包通常 5–10 分钟。控制器计时包含模型等待和工具调用，排队不消耗主动预算。环境最大存续时间为总预算四倍且至少一小时。每假设最多两次测试，重试需要新增证据说明。耗尽预算的未执行包是 SKIPPED，真实超时才是 TIMED_OUT。

超时、取消在途测试、清理失败、未知环境状态或进程异常恢复会停止环境复用。已获得的证据仍保留，清理失败也不会自动抹去有效发现。静态报告继续完成，并列明测试残留与人工处理要求。

每个审计的证据保存在 `reports/runtime-testing/<audit_id>/`：授权摘要、状态、每包输入/结果、脱敏工具证据与封存 evidence-set。环境原文和 worker 附件放在受控私有状态目录，工作台 API 不返回凭证。多个审计共享的环境锁位于状态目录的 `runtime-environment-leases/`；异常退出遗留锁必须在确认本次浏览器与测试数据已处理后由操作者移除，平台不会自动清锁并重连。

三方 intake、角色与 routing 使用 v3；最终模型也使用 v3。没有源码映射的中期候选仍接受三方复核，在报告中单列为 RUNTIME_ONLY、source_mapping=UNKNOWN；不会伪造源码位置、计入源码漏洞数量或直接套用源码 CVSS/攻击链。历史 v1/v2 制品仍按原契约读取。

## 运行与回归

在支持的 Windows/Linux 主机直接运行平台，禁止使用容器。新控制器仍使用项目固定版本的 Chrome DevTools MCP；没有真实测试环境时，可以运行仅使用伪浏览器的回归：

```sh
npm --prefix .opencode run test:runtime-testing
npm --prefix .opencode run test:truth-validation-contract
npm --prefix .opencode run test:stage-agent-contract
npm --prefix .opencode run test:stage-delivery-contract
npm --prefix .opencode run test:audit-workbench
npm --prefix .opencode run test:config
```

经本次会话明确授权，已在 macOS 上完成可移植回归：主测试入口的 23 个脚本组分别执行并全部通过。真实 Chrome DevTools 联调与 Windows/Linux 原生运行验收尚未执行。上线前仍需在受支持主机复测，并用另行明确授权的 loopback 测试环境验证实际登录隔离、浏览器代理拦截、应用证据与清理路径。详细范围及修正记录见 [macOS 回归验证记录](macos-regression-verification.md)。

新增运行测试的 31 个用例均已通过，覆盖缺少环境时零启动、新旧协议分流、身份隔离、默认 HTTPS 端口与 loopback 代理、初始化和队列取消竞态、预算与超时、清理失败保留证据、异常恢复、输入与证据归属绑定、不可用状态自动封存、XSS 应用证据要求以及 v3 报告收尾。这里的浏览器与 worker 使用替身；代理用例只启动用例自身的临时 loopback HTTP 服务，不连接被审计目标。

macOS 可移植测试须经明确授权，使用以下显式开关；它仅放行使用替身的测试文件，不改变平台与真实浏览器的 Windows/Linux 运行限制：

```sh
AUDIT_ALLOW_MACOS_PORTABLE_TESTS=1 npm --prefix .opencode test
```

Agent 的命令与字段说明见 [运行测试执行契约](../.opencode/lib/runtime-testing/workflow.md)。人工验证入口继续生成独立 sidecar；补充环境、扩大授权或重新生成终稿通过新建审计保留版本，不覆盖既有结论。
