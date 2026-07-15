---
name: java-csrf
description: "Detect Java Cross-Site Request Forgery (CSRF) by locating state-changing endpoints that accept cookie-authenticated browser requests without effective CSRF defenses (token, SameSite, custom header, double-submit). Use for Java CSRF audits, CWE-352 review, Spring Security csrf().disable(), cookie-session JSON APIs without CSRF header, GET-based mutations, form POST without token, and token-not-bound-to-session analysis. Keywords: CSRF, CWE-352, A01:2021, csrf().disable(), CsrfFilter, _csrf, X-CSRF-TOKEN, SameSite, Cookie auth, session fixation adjacent, state-changing GET."
license: MIT
compatibility: opencode
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D2
  weakness: csrf
  source: vuln_skill_builder
---

# Java CSRF Detection Skill

## Goal

识别依赖浏览器自动附带凭证（Cookie / 会话）的状态变更入口，在缺乏有效 CSRF 防护（同步器令牌、双重提交 Cookie、强制自定义头、SameSite=Strict/Lax 有效策略、Origin/Referer 校验）时，可被跨站请求触发的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 认证与会话机制说明（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 Spring Security / Spring MVC / Servlet session / 表单登录 / Cookie 会话 / JWT-in-cookie，加载对应 framework model。
2. **L1 候选点定位**：定位状态变更端点与 CSRF 关闭/缺失配置（grep → Semgrep → Joern），输出 `SinkCandidate`（状态变更动作），不是漏洞。
3. **L2 认证与凭证分析**：确认端点是否依赖 Cookie/Session 自动凭证；区分 Bearer header-only 与 Cookie 会话。
4. **L3 防护分析**：识别 CSRF token、CsrfFilter、SameSite、自定义头强制、Origin/Referer 检查；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认浏览器可达、非测试/死代码、状态变更语义真实、权限前提。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用概念验证方案（禁止通用 PoC 盲打；本 Skill 仅概念级验证）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：Spring Security 配置、csrf disable、状态变更映射、Cookie/Session
2. **Semgrep**：csrf().disable()、缺 token 的 POST/PUT/DELETE、GET 变更、Cookie JSON API
3. **Joern**：跨方法调用链、会话读、状态写操作
4. **CodeQL**：可构建项目的补充分析
5. **LLM**：业务语义、是否状态变更、防护有效性、SameSite/浏览器前提研判

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

- 未发现状态变更端点或 CSRF 相关配置缺口
- 端点仅接受非自动凭证（如 Authorization: Bearer 且无 Cookie 会话）
- 所有可达状态变更路径均有强 CSRF 防护（token 绑定会话 / 强制自定义头 / 有效 SameSite+安全方法策略）
- 无法建立「跨站浏览器 + 自动凭证 + 状态变更」的可信组合
- 证据不足以满足 Evidence Contract

## Output Rules

- 仅存在 `csrf().disable()` 配置命中 ≠ 漏洞；需绑定真实状态变更入口与 Cookie 认证
- 纯 JWT-in-header API（无 Cookie）通常不在 CSRF 攻击面
- CORS 放宽与 CSRF 相关但不等价；不得仅凭 CORS 配置报 CSRF Finding
- 本 Skill **仅概念级验证**，不生成可执行 exploit/PoC 载荷
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：入口与方法、凭证如何自动附带、状态如何变更、防护为何无效、跨站如何触发、证据如何支撑

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D2** / weakness `csrf`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-csrf-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-csrf-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-csrf-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`, `java-deserialization-review`) for cross-cutting coverage.
