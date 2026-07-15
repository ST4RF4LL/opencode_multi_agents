---
name: java-open-redirect
description: "Detect Java Open Redirect / Unvalidated Redirects (CWE-601) by locating attacker-controlled redirect targets reaching sendRedirect, Location headers, Spring redirect: prefix, or RedirectView without effective destination allowlisting. Use for Java open-redirect audits, unvalidated redirect review, phishing redirect paths, protocol-relative bypass, path-relative URL bypass, and weak startsWith checks on redirect URLs. Keywords: open redirect, unvalidated redirect, CWE-601, A01:2021, sendRedirect, setHeader Location, redirect:, RedirectView, protocol-relative //evil.example, startsWith bypass, returnUrl, next, continue, callback."
license: MIT
compatibility: opencode
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D6
  weakness: open-redirect
  source: vuln_skill_builder
---

# Java Open Redirect Detection Skill

## Goal

识别攻击者可控的重定向目标（完整 URL / protocol-relative / path-relative 逃逸 / Spring `redirect:` 前缀拼接）流向浏览器跳转响应操作，且缺乏有效目标约束（固定映射、解析后 host/scheme allowlist、相对路径白名单）的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 Servlet / Spring MVC（RedirectView、`redirect:` 前缀、ResponseEntity 3xx），加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`，不是漏洞。
3. **L2 数据流分析**：从 sink 反向扩展调用链；执行 source-to-sink 可达分析。
4. **L3 防护分析**：识别固定目标映射、解析后 host/scheme allowlist、相对路径强制、弱 startsWith/contains；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API 入口、参数可控性、非测试/死代码、权限与 feature flag。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 payload）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与危险 API 关键词
2. **Semgrep**：局部危险模式（用户 URL 直接 sendRedirect、`redirect:`+param、弱前缀校验、Location 头注入）
3. **Joern**：跨方法调用链与数据流
4. **CodeQL**：可构建项目的补充分析
5. **LLM**：业务语义、重定向目标控制面（full URL / protocol-relative / path-relative）、防护有效性研判

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

- 未发现相关 redirect sink（sendRedirect / Location / redirect: / RedirectView）
- sink 目标完全由常量/固定映射产生且用户输入不进入 redirect destination
- 所有可达路径均经有效解析后 host/scheme allowlist，或强制同站相对路径
- 无法建立外部输入到重定向目标的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- 危险 redirect API 命中 ≠ 漏洞
- 仅 path/query 可控且强制同站相对路径时，通常非 open redirect，不得直接报 Finding
- SSRF（服务端 fetch 用户 URL）不在本 Skill 范围，边界见 `scope/boundaries.yaml` / `java-ssrf`
- 纯 XSS（反射/存储脚本执行）不在本 Skill 范围
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、流向哪、中间经过什么、防护为何无效、攻击者控制了什么 redirect 目标、如何证明浏览器会跳转到不可信域名

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D6** / weakness `open-redirect`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-open-redirect-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-open-redirect-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-open-redirect-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`, `java-deserialization-review`) for cross-cutting coverage.
