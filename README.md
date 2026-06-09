# OpenCode Multi-Agent Source Security Audit

这是一套项目级 OpenCode 配置，用于对源码项目做多 agent 安全审计。当前目录下的 `.opencode/` 包含主控 agent、信息收集 agent、三个语言专用源码审计 agent，以及漏洞验证 agent。

## Agent topology

- `security-audit-orchestrator`: 主控入口，负责拆分任务、按语言路由、汇总报告。
- `security-intel-collector`: 信息收集，输出攻击面和语言路由。
- `c-cpp-source-auditor`: C/C++ 源码审计。
- `java-source-auditor`: Java/JVM 源码审计。
- `python-source-auditor`: Python 源码审计。
- `vulnerability-validator`: 对候选漏洞做安全、授权、本地化验证。
- `security-skill-optimizer`: 根据验证结果优化审计 skill、Joern 规则、漏洞案例和误报案例。

## Maintain skills and MCP

可维护性核心在 `.opencode/agent-manifest/`：

- `roles.json`: 角色边界和输入输出。
- `skill-map.json`: 每个 subagent 可用的 skill 清单和命名前缀。
- `mcp-map.json`: 每个 subagent 可用的 MCP 工具通配符。
- `artifact-policy.json`: 临时目录、SARIF/JSON 报告和清理策略。
- `naming.md`: 新增 skill/MCP 时的命名和维护规则。

所有 skill 按 subagent 分组放置，目录层级固定为 `.opencode/skills/<subagent-skill-group>/<skill-name>/SKILL.md`，例如 `.opencode/skills/c-cpp-subagent/c-cpp-vuln1-skill/SKILL.md`。分组目录不放 `SKILL.md`，只放 `collection.json` 和维护说明；OpenCode 会递归发现子目录里的原子 skill。

添加自有 skill 时，放到对应 subagent 分组下，并优先使用对应角色的命名前缀，例如 `c-cpp-*`、`java-*`、`python-*`、`validation-*`。然后把 skill 名称加入对应分组目录的 `collection.json`；如果它应该成为默认必需 skill，再更新 `skill-map.json`。

添加自有 MCP 时，先在 `.opencode/opencode.json` 的 `mcp` 中替换或新增服务器定义，再在 `mcp-map.json` 和对应 agent frontmatter 的权限中加入 `<server>_*`。

## Shared audit assets

公共审计资产位于 `.opencode/shared/security-audit/`，所有 subagent 都可以读取：

- `joern-rules/`: Joern 规则、规则说明和规则索引。
- `vulnerability-cases/`: 已确认或高可信漏洞案例。
- `false-positive-cases/`: 误报案例和规则收敛依据。
- `rule-results/`: Joern/静态扫描结果摘要，用于后续优化。

默认只有 `security-skill-optimizer` 负责修改这些资产。Orchestrator 会根据 `vulnerability-validator` 的验证结果决定是否拉起它：

- `confirmed`: 优化相关 `SKILL.md`、补充/收敛 Joern 规则、加入漏洞案例。
- `likely`: 在缺失条件明确时补充审计指导或 pending 案例。
- `needs-info`: 补充证据要求，减少后续不确定性。
- `false-positive`: 加入误报案例，并收敛 skill 或规则。

## Temporary artifacts and reports

所有任务运行期产物统一放在当前目录的 `tmp/` 下。`tmp/` 默认被 `.gitignore` 忽略，只保留 `tmp/.gitkeep` 和 `tmp/README.md`。

约定路径：

- 静态分析报告统一使用 SARIF 2.1.0：`tmp/reports/sarif/<agent-name>.<agent-session-id>.sarif`
- 漏洞挖掘 subagent/session 结果统一使用 JSON：`tmp/reports/vulnerability-mining/<agent-name>.<agent-session-id>.json`
- 其他临时文件、中间过程件、脚本、临时规则：`tmp/work/<agent-name>/<agent-session-id>/`

一个 agent session 对应一个 SARIF；一个漏洞挖掘 agent session 对应一个 JSON。多个静态分析工具在同一 session 内运行时，应合并到同一个 SARIF 的多个 `runs`。

Orchestrator 在任务结束前会读取并汇总这些报告，然后清理 `tmp/`。有复用价值的脚本、Joern 规则、静态规则、漏洞案例、误报案例，必须先由 `security-skill-optimizer` 提升到 `.opencode/skills/` 或 `.opencode/shared/security-audit/`。

## Usage

在需要审计的源码项目根目录运行 OpenCode，并使用本配置目录作为项目配置，或把 `.opencode/` 复制到目标项目根目录。

推荐入口：

```text
@security-audit-orchestrator 对当前项目做一次源码安全审计，先信息收集，再按语言调用对应审计 agent，最后验证高风险候选项。
```

也可以分阶段调用：

```text
@security-intel-collector 识别当前项目的攻击面和语言路由。
@c-cpp-source-auditor 审计 native/C/C++ 安全问题。
@java-source-auditor 审计 Java/JVM 安全问题。
@python-source-auditor 审计 Python 安全问题。
@vulnerability-validator 验证以下候选漏洞是否可利用：...
@security-skill-optimizer 根据以下验证结果优化 skill、Joern 规则和案例库：...
```

## MCP defaults

`context7` 和 `gh_grep` 已按官方远程 MCP 示例配置，但默认 `enabled: false`。其余 MCP 是可替换占位，例如 `semgrep`、`codeql`、`joern`、`cpp_index`、`jvm_index`、`python_index`、`audit_lab`。

占位 MCP 需要替换为你本机实际可运行的 `type/command` 或 `type/url` 后再启用。

## Safety defaults

默认配置是只读审计：

- `edit: deny`
- `security-skill-optimizer` 例外：只允许修改 `.opencode/skills/**/SKILL.md`、skill 集合清单和 `.opencode/shared/security-audit/` 下的规则/案例资产。
- Orchestrator 和源码审计 subagent 例外：只允许在 `tmp/` 下写入运行期报告和临时产物。
- `external_directory: ask`
- bash 默认需要确认，只有 `pwd`、`ls`、`find`、`rg`、`git status`、`git log`、`git grep`、`git ls-files` 等只读命令自动允许。
- 漏洞验证 agent 只允许本地、授权、非破坏性验证，不允许真实攻击、持久化、外连利用或数据窃取。
