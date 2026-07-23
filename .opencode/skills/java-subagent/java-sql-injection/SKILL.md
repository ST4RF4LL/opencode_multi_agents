---
name: java-sql-injection
description: "Detect Java SQL injection by locating attacker-controlled input reaching SQL/JPA/MyBatis query sinks without effective parameterization or allowlisting. Use for Java SQLi audits, CWE-89 review, JDBC/MyBatis/Hibernate/JPA/Spring Data query analysis, order-by/column-name injection, and second-order SQL injection. Keywords: SQL injection, SQLi, CWE-89, JDBC, PreparedStatement, Statement.execute, MyBatis ${}, Hibernate createQuery, JPA native query, Spring JdbcTemplate, order by injection, second-order SQLi."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D1
  weakness: sql-injection
  source: vuln_skill_builder
---


# Java SQL Injection Detection Skill

## Goal

识别攻击者可控输入流向 SQL 查询构造/执行点，且缺乏有效参数化或标识符约束的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 JDBC / MyBatis / Hibernate / JPA / Spring Data / JdbcTemplate 等，加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`，不是漏洞。区分 **JPA QL vs SQL**：`createQuery` = JPQL/HQL（`jpa-jpql-injection`），`createNativeQuery`/`createSQLQuery` = 原生 SQL（`orm-native-query`）；两者都因字符串拼接而危险，修复均为常量查询 + `setParameter`。
3. **L2 数据流分析**：从 sink 反向扩展调用链；执行 source-to-sink 可达分析。
4. **L3 防护分析**：识别参数化、标识符白名单、转义、ORM 安全 API；按 sanitizer 分级评估。JPQL 侧优先确认命名参数而非仅“用了 JPA”。
5. **L4 入口与可达性**：确认 API 入口、参数可控性、非测试/死代码、权限与 feature flag。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`（含 case-004 JPQL）。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 payload）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与危险 API 关键词
2. **Semgrep/OpenGrep**：通过 `semgrep_scan` 执行本地兼容规则，定位字符串拼接 SQL、`${}`、动态 order-by
3. **Joern**：跨方法调用链与数据流
4. **LLM**：业务语义、标识符注入、二次注入、防护有效性研判

## Progressive Loading

| 阶段 | 加载内容 |
|------|----------|
| 初始化 | `SKILL.md`, `manifest.yaml`, `scope/definition.yaml` |
| 技术栈识别后 | `models/frameworks/<stack>.yaml`, `models/sources.yaml`, `models/sinks.yaml` |
| 规则执行 | `rules/grep/keywords.yaml`, `rules/semgrep/*`, `rules/joern/*` |
| 命中候选后 | `models/sanitizers.yaml`, `models/propagators.yaml`, `analysis/*` |
| 语义研判 | 相似 `cases/*/lessons.yaml` + `references/cases.md`（真实 GHSA/H1） |
| 验证 | `validation/*` |
| 输出 | `evidence/contract.yaml`, `evidence/finding-schema.yaml` |

## Real-Case Joern Rules

命中 L1 后按模式加载 `rules/joern/derived/`（由 GHSA/H1 提炼）：

| 模式 | 脚本 | 来源案例 |
|------|------|----------|
| 动态标识符 | `derived/dynamic-identifier.sc` | CVE-2026-26198 |
| Map key→SQL | `derived/map-key-to-sql.sc` | CVE-2025-65896 |
| 任意 SQL 执行 | `derived/raw-sql-execution.sc` | CVE-2024-12909 |
| 运算符/连接符 | `derived/operator-connector-inject.sc` | H1 #3335709 |
| 动态 filter/join | `derived/dynamic-filter-fragment.sc` | H1 #3292573 |
| 路径参数→SQL | `derived/path-param-to-sql.sc` | H1 #2958619 等 |

映射表：`references/pattern-to-joern.yaml`。案例正文：`references/cases.md`。

## Stop Conditions

- 未发现相关 SQL sink
- sink 查询完全由常量/安全 API 构造且用户输入仅作绑定参数
- 所有可达路径均经有效参数化或完整标识符白名单
- 无法建立外部输入到危险 SQL 构造的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- 危险 API 命中 ≠ 漏洞
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、流向哪、中间经过什么、防护为何无效、攻击者控制了什么、如何证明可达

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D1** / weakness `sql-injection`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-sql-injection-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-sql-injection-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-sql-injection-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`) for cross-cutting coverage.
