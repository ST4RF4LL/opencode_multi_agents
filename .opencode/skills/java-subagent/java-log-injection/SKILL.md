---
name: java-log-injection
description: "Detect Java log injection and CRLF log forging by locating attacker-controlled input reaching logging sinks without structured logging or newline sanitization. Use for Java log injection audits, CWE-117/CWE-93 review, Log4j2/Logback/SLF4J string-concat log messages, forged log entries, and log viewer XSS risk. Keywords: log injection, CRLF injection, CWE-117, CWE-93, log forging, Log4j2, Logback, SLF4J, logger.info concat, parameterized logging, JsonTemplateLayout, structured logging. Not primary for Log4Shell/JNDI lookup (adjacent boundary only)."
license: MIT
compatibility: opencode
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D8
  weakness: log-injection
  source: vuln_skill_builder
---


# Java Log Injection Detection Skill

## Goal

识别攻击者可控输入流向日志消息构造/输出点，且缺乏结构化日志或换行/控制字符约束，可导致伪造日志条目（CRLF）或日志查看侧影响的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）
- 日志查看/采集方式（可选，影响 XSS 与 SIEM 解析风险）

## Workflow

1. **L0 技术栈识别**：识别 Log4j2 / Logback / SLF4J / JUL / commons-logging 等，加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`，不是漏洞。
3. **L2 数据流分析**：从 sink 反向扩展调用链；执行 source-to-sink 可达分析（关注 message 参数与字符串拼接）。
4. **L3 防护分析**：识别参数化日志、结构化 JSON 布局、换行剥离、长度限制；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API 入口、参数可控性、非测试/死代码、日志是否进入共享/审计视图。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 payload；禁止破坏性测试）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与日志 API 关键词
2. **Semgrep**：字符串拼接 log 消息、非参数化 logger 调用
3. **Joern**：跨方法调用链与数据流
4. **CodeQL**：可构建项目的补充分析
5. **LLM**：业务语义、CRLF 可伪造性、日志查看路径 XSS 风险、防护有效性研判

## Progressive Loading

| 阶段 | 加载内容 |
|------|----------|
| 初始化 | `SKILL.md`, `manifest.yaml`, `scope/definition.yaml` |
| 技术栈识别后 | `models/frameworks/<stack>.yaml`, `models/sources.yaml`, `models/sinks.yaml` |
| 规则执行 | `rules/grep/keywords.yaml`, `rules/semgrep/*`, `rules/joern/*` |
| 命中候选后 | `models/sanitizers.yaml`, `models/propagators.yaml`, `analysis/*` |
| 语义研判 | 相似 `cases/*/lessons.yaml` |
| 验证 | `validation/*` |
| 输出 | `evidence/contract.yaml`, `evidence/finding-schema.yaml` |

## Adjacent Boundary (Not Primary)

- **Log4Shell / JNDI lookup**（CWE-502 等）：消息中的 `${jndi:...}` 由 Log4j 查找机制触发，与 CRLF 日志伪造不同。若发现 lookup 相关配置/版本问题，标记为 adjacent finding，不作为本 Skill 主结论，除非数据流自然同时成立。
- **敏感数据日志**（口令/token 入日志）：归 `java-sensitive-data-logging` 类 Skill，本 Skill 仅在“可控输入影响日志结构”时覆盖。

## Stop Conditions

- 未发现相关 logging sink
- 日志消息为编译期常量模板，用户输入仅作参数化占位符且布局为结构化 JSON
- 所有可达路径均经有效换行剥离/长度限制/结构化字段绑定
- 无法建立外部输入到日志消息内容的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- 危险 logger API 命中 ≠ 漏洞
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、流向哪、中间经过什么、防护为何无效、攻击者控制了什么（换行/字段/消息体）、如何证明可达并影响日志完整性或查看侧安全

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D8** / weakness `log-injection`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-log-injection-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-log-injection-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-log-injection-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`) for cross-cutting coverage.
