---
name: java-xss
description: "Detect Java server-side Cross-Site Scripting (XSS) by locating attacker-controlled input reaching HTTP response writers, JSP/Thymeleaf/FreeMarker unescaped outputs, or wrong-context encoding without effective output encoding/sanitization. Use for Java XSS audits, CWE-79 review, JSP EL, Thymeleaf th:utext, FreeMarker ?no_esc, Spring MVC response body/writer analysis, HTML/JS/CSS context encoding, OWASP Java Encoder, and HTML Sanitizer. Keywords: XSS, cross-site scripting, CWE-79, reflected XSS, stored XSS, JSP, ${}, th:utext, response.getWriter, PrintWriter, Encode.forHtml, HtmlPolicyBuilder, context-aware encoding."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D1
  weakness: xss
  source: vuln_skill_builder
---


# Java XSS Detection Skill

## Goal

识别攻击者可控输入流向服务端 HTTP 响应写出点（HTML/JS/CSS 上下文），且缺乏有效上下文编码或安全消毒的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 JSP / Thymeleaf / FreeMarker / Spring MVC / Servlet 等，加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`，不是漏洞。
3. **L2 数据流分析**：从 sink 反向扩展调用链；执行 source-to-sink 可达分析。
4. **L3 防护分析**：识别上下文编码（Encode.forHtml/forJs/forCss 等）、HTML Sanitizer、模板默认转义；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API/页面入口、参数可控性、非测试/死代码、权限与 feature flag。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 payload 作为通用 exploit）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与危险写出 API / 未转义模板语法关键词
2. **Semgrep/OpenGrep**：通过 `semgrep_scan` 执行本地兼容规则，定位 getWriter.print、th:utext、JSP 未转义、错误上下文编码
3. **Joern**：跨方法调用链与数据流
4. **LLM**：输出上下文（HTML body / attribute / JS / CSS / URL）、编码是否匹配、消毒策略有效性研判

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

## Stop Conditions

- 未发现相关 response/template sink
- sink 输出完全由常量产生，用户输入未进入响应体
- 所有可达路径均经匹配上下文的强编码或有效 HTML 消毒
- 无法建立外部输入到危险写出点的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- 危险 API 命中 ≠ 漏洞
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 不提供脱离目标的通用 XSS payload 作为可复用 exploit
- 每个 Finding 必须回答：输入从哪来、流向哪、输出上下文是什么、编码/消毒为何无效、攻击者控制了什么、如何证明可达

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D1** / weakness `xss`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-xss-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-xss-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-xss-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`) for cross-cutting coverage.
