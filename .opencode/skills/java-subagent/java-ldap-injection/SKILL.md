---
name: java-ldap-injection
description: "Detect Java LDAP injection by locating attacker-controlled input reaching LDAP filter or DN construction without effective encoding or parameterized filters. Use for Java LDAP audits, CWE-90 review, JNDI DirContext.search filter analysis, Spring LDAP LdapQuery/LdapTemplate filter building, DN injection, and authentication-bypass via filter metacharacters. Keywords: LDAP injection, CWE-90, DirContext.search, NamingEnumeration, filter concat, Spring LdapEncoder, LdapQueryBuilder, SearchControls, distinguished name injection, JNDI LDAP."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D1
  weakness: ldap-injection
  source: vuln_skill_builder
---


# Java LDAP Injection Detection Skill

## Goal

识别攻击者可控输入流向 LDAP 过滤器（filter）或 DN 构造/搜索操作，且缺乏有效编码、参数化过滤或 allowlist 的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 JNDI (`javax.naming` / `javax.naming.directory`) / Spring LDAP / UnboundID / Apache Directory LDAP API，加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`，不是漏洞。
3. **L2 数据流分析**：从 sink 反向扩展调用链；执行 source-to-sink 可达分析。
4. **L3 防护分析**：识别 filter 编码（`LdapEncoder` / `encodeFilterValue`）、参数化 `LdapQuery`、DN 编码、allowlist；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API 入口、参数可控性、非测试/死代码、权限与 feature flag。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 payload）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与危险 API 关键词
2. **Semgrep**：局部危险模式（filter 字符串拼接、DN 拼接、未编码用户输入）
3. **Joern**：跨方法调用链与数据流
4. **CodeQL**：可构建项目的补充分析
5. **LLM**：业务语义、认证旁路逻辑、防护有效性研判

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

- 未发现相关 LDAP sink
- filter/DN 完全由常量或安全 API 构造，且用户输入仅作已编码/参数化绑定
- 所有可达路径均经有效 filter 编码、参数化 filter 或完整 allowlist
- 无法建立外部输入到危险 LDAP 构造的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- 危险 API 命中 ≠ 漏洞
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、流向哪、中间经过什么、防护为何无效、攻击者控制了什么、如何证明可达

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D1** / weakness `ldap-injection`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-ldap-injection-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-ldap-injection-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-ldap-injection-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`) for cross-cutting coverage.
