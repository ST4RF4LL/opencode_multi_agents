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

## Skill management

Skill 按 subagent 分组，目录结构固定为 `.opencode/skills/<subagent-skill-group>/<skill-name>/SKILL.md`，例如 `.opencode/skills/c-cpp-subagent/c-cpp-memory-safety-review/SKILL.md`。分组目录本身不包含 `SKILL.md`，只放 `collection.json` 和维护说明，OpenCode 会递归发现子目录中的原子 skill。

### 自动映射

Skill 到 agent 的映射通过目录约定和 `collection.json` 自动完成，无需手动同步多个文件：

- **`collection.json`** — 每个 skill 分组目录下的唯一 skill 清单，其中的 `owner_agent` 字段定义了该组 skill 归属的 agent。
- **`skill-map.json`** — 文档参考，记录所有 `collection → owner_agent` 映射关系，不再重复维护 skill 列表。
- **agent frontmatter** — 所有 agent 的 `skill` 权限已统一设为 `"*": allow`，任意 skill 被发现后即可使用。

> 新增 skill 只需：放入对应分组目录 → 创建 `SKILL.md` → 将 skill 名称加入 `collection.json`。无需修改其他配置文件。

### 命名前缀约定

| 角色 | 推荐前缀 |
|------|----------|
| 信息收集 | `recon-*`, `intel-*`, `dependency-intel-*`, `attack-surface-*` |
| C/C++ 审计 | `c-cpp-*`, `cpp-*`, `native-security-*`, `memory-safety-*` |
| Java/JVM 审计 | `java-*`, `jvm-*`, `spring-security-*`, `deserialization-*` |
| Python 审计 | `python-*`, `py-*`, `django-security-*`, `flask-security-*`, `fastapi-security-*` |
| 漏洞验证 | `validation-*`, `poc-*`, `exploitability-*` |
| Skill 优化 | `optimization-*`, `skill-optimization-*`, `joern-rule-*`, `audit-casebase-*` |

## Maintain skills and MCP

可维护性核心在 `.opencode/agent-manifest/`：

- `roles.json` — 角色边界和输入输出。
- `skill-map.json` — collection 到 agent 的映射关系（文档参考）。
- `mcp-map.json` — 每个 subagent 可用的 MCP 工具通配符。
- `artifact-policy.json` — 报告格式、临时目录和清理策略。
- `naming.md` — 新增 skill/MCP 时的命名和维护规则。

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

审计报告输出到项目根目录的 `reports/`，临时产物存放在 `tmp/` 下按任务模块名称分目录管理。`tmp/` 被 `.gitignore` 忽略，只保留 `tmp/.gitkeep` 和 `tmp/README.md`。

约定路径：

- 静态分析报告（SARIF 2.1.0）：`reports/sarif/<agent-name>.<agent-session-id>.sarif`
- 漏洞挖掘结果（JSON）：`reports/vulnerability-mining/<agent-name>.<agent-session-id>.json`
- 临时文件、脚本、规则：`tmp/<task-module>/`

一个 agent session 对应一个 SARIF；一个漏洞挖掘 session 对应一个 JSON。多个静态分析工具在同一 session 内运行时，应合并到同一个 SARIF 的多个 `runs`。

Orchestrator 在任务结束前会读取并汇总 `reports/` 下的报告，然后仅清理 `tmp/` 下的任务子目录（保留 `.gitkeep` 和 `README.md`）。有复用价值的脚本、规则、案例，必须先由 `security-skill-optimizer` 提升到 `.opencode/skills/` 或 `.opencode/shared/security-audit/`。

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

## Permission defaults

默认配置已放开编辑和外部访问权限，便于开发和调试：

- `edit: allow` — 所有 agent 均可编辑文件。
- `external_directory: allow`, `webfetch: allow`, `websearch: allow` — 允许外部目录访问和网络操作。
- `skill: "*": allow` — 所有 agent 可使用任意发现的 skill，skill 通过目录约定自动映射。
- `bash` 默认需要确认，`pwd`、`ls`、`find`、`rg`、`git status/log/grep/ls-files` 等只读命令自动允许，`mkdir` 和清理命令在审计相关路径下自动允许。
- 漏洞验证 agent 只允许本地、授权、非破坏性验证，不允许真实攻击、持久化、外连利用或数据窃取。
