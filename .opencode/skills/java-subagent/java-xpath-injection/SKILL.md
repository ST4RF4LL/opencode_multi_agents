---
name: java-xpath-injection
description: "Detect Java XPath injection (CWE-643) by locating attacker-controlled input reaching XPath compile/evaluate sinks without XPath Variable Resolver or parameterized $var binding. Use for Java XPath audits, javax.xml.xpath / Saxon query analysis, XML node selection injection, and OWASP Java Security CS XPath guidance. Keywords: XPath injection, CWE-643, XPath.compile, XPath.evaluate, XPathExpression, XPathVariableResolver, DocumentBuilder XPath, parameterized XPath, $bookId."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D1
  weakness: xpath-injection
  source: vuln_skill_builder
---


# Java XPath Injection Detection Skill

## Goal

识别攻击者可控输入流向 XPath 查询构造/编译/求值点，且缺乏有效变量绑定（XPath Variable Resolver / `$var`）或结构化约束的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 `javax.xml.xpath` / `jakarta.xml.xpath` / Saxon / DOM+XPath 用法，加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`，不是漏洞。
3. **L2 数据流分析**：从 sink 反向扩展调用链；执行 source-to-sink 可达分析。
4. **L3 防护分析**：识别 `XPathVariableResolver`、编译期常量表达式、`$var` 参数化、输入白名单；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API 入口、参数可控性、非测试/死代码、权限与 feature flag。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 payload）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与危险 API 关键词（XPath.compile / evaluate / 字符串拼接）
2. **Semgrep/OpenGrep**：通过 `semgrep_scan` 执行本地兼容规则，定位拼接 XPath、format 进 compile/evaluate
3. **Joern**：跨方法调用链与数据流
4. **LLM**：业务语义、变量解析器有效性、谓词/轴操纵研判

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

## Scope Notes

- **Focus**: XPath injection (query structure influenced by untrusted input).
- **Adjacent / out of scope here**: `DocumentBuilderFactory` XXE (CWE-611) — track separately as `java-xxe`. DocumentBuilder may appear only as XML document load context for XPath evaluation, not as the injection sink.
- Do not report XXE solely because XPath is used; do not dismiss XPath injection because XXE hardening is present.

## Stop Conditions

- 未发现相关 XPath sink
- XPath 表达式完全由常量/安全模板产生，且用户输入仅经 `$var` / VariableResolver 绑定
- 所有可达路径均经有效参数化或完整允许列表映射
- 无法建立外部输入到危险 XPath 构造的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- 危险 API 命中 ≠ 漏洞
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、流向哪、中间经过什么、防护为何无效、攻击者控制了什么、如何证明可达

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D1** / weakness `xpath-injection`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-xpath-injection-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-xpath-injection-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-xpath-injection-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`) for cross-cutting coverage.
