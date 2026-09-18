# Focus Area 交付检查与 watchdog

本功能核对已分派任务是否都有合法交付，不声称已经发现所有漏洞，也不替代文件、函数和漏洞证据的语义审查。

## 交付时检查

专业 Agent 将工作包交付件写入 `$AUDIT_REPORTS_ROOT/audit-todo/<audit_id>/<packet_id>.json`，然后执行：

```sh
node "$AUDIT_TODO_CLI" check \
  --todo "$AUDIT_TODO_PATH" \
  --packet <packet_id> \
  --handoff <交付件绝对路径> \
  --reports-root "$AUDIT_REPORTS_ROOT"
```

程序只读检查本包领取集合，返回 `missing_items`、`invalid_items`、`errors` 与 `complete`。遗漏、重复、越域 ID、三视角缺失、摘要或身份不符、缺少跳过原因都会使检查以非零状态退出。每条遗漏或无效项保留 Focus Area、assignment、domain 和责任 Agent。检查失败不修改任何任务状态；修正后仍由 Orchestrator 执行 `complete`，该操作会重新执行相同检查。

## 提醒到达方式

- 工作台现有 15 秒 watchdog 周期检查本地分派，变化后写入 `audit.focus-area.reminder` 事件和中文运行日志；完整结果存入该任务状态目录的 `focus-area-coverage.json`。状态不变不重复写事件。
- OpenCode 插件在专业 `task` 返回、会话工具结果以及下一轮模型调用前提供提醒。责任域来自会话 Agent 或 `task.subagent_type`；提醒最多列出 12 项，相同会话、相同结果在 60 秒内去重。检查失败显示 `UNAVAILABLE`，不能解释为覆盖完成。
- 提醒涵盖尚未领取、未提交报告、报告无效、已提交但未验收、失败和租约过期。插件只读，不启动新 Agent、不修改队列、不打断正在运行的分析。Orchestrator 负责继续分派或让原责任 Agent 补齐。
- 新任务将绑定 Plan 文件摘要，并比较 Plan 与 TODO 的任务集合。计划变更或任务遗漏阻止声明完成；历史任务仍检查可用的计划集合，不补造历史摘要。

插件由 Runner 显式加载，因此禁用被审计项目配置也不会禁用本平台提醒。更新后新启动或断点恢复的任务加载该插件；已经运行的 OpenCode 进程不会热加载。

## 特殊情况跳过

跳过继续使用终态 `GAP`，增加显式标识，兼容已有任务状态：

```json
{
  "item_id": "todo:<coverage-unit-id>",
  "status": "GAP",
  "gap_kind": "SKIPPED",
  "gap_reason": "依赖模块源码未提供，本次无法审查该模块的权限校验。"
}
```

每个跳过任务都必须单独登记，不能省略交付项、自动转换遗漏项，或使用 `DONE` 表示跳过。普通 `GAP` 继续保留原语义，不自动改成 `SKIPPED`。

验收后，跳过项不重复催办，不计入 `done`；`skipped` 是 `gap` 的子集。覆盖摘要为 `PARTIAL`，可以通过 `policy-final` 收尾。摘要和最终模型的 `focus_area_exceptions` 保留 Area、assignment、domain、责任 Agent、标识及原因；中文报告单列“Focus Area 跳过与未完成清单”。收尾门禁再次比对本地跳过清单，拒绝漏写或改写原因的报告。

## 验证

`npm --prefix .opencode run test:audit-todo` 包含 watchdog 回归，覆盖遗漏不改状态、无效报告、无理由跳过、Plan 漂移、提醒去重和责任域隔离、报告渲染及收尾防漏记。工作台回归还检查 Runner 是否实际配置了插件。

OpenCode 接入依据：[官方插件文档](https://opencode.ai/docs/plugins/)，钩子参数同时与仓库安装的 `@opencode-ai/plugin` 类型定义核对。
