---
name: java-injection-review
description: Review Java/JVM code for SQL, JPQL, LDAP, XPath, template, expression, command, and class-loading injection issues.
license: MIT
compatibility: opencode
metadata:
  role: java-source-auditor
  collection: java-subagent
---

# Java Injection Review

Use this skill when user-controlled data reaches query builders, expression engines, templates, command execution, or dynamic loading.

## Focus Areas

- SQL, JPQL, NoSQL, LDAP, XPath, and search query construction.
- SpEL, OGNL, template engines, scripting engines, reflection, and dynamic class loading.
- Process execution with string commands, shell invocation, environment control, or unsafe argument construction.
- SSRF-related URL construction when injection affects network destinations or headers.
- Sanitizer misuse, partial escaping, and framework APIs that look safe but concatenate raw fragments.

## Progressive Deep Packs

When sinks or frameworks match, load the deep vuln skill and its progressive assets (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`):

| Signal | Load skill |
|--------|------------|
| JDBC / MyBatis / JPA / JdbcTemplate / `ORDER BY` | `java-sql-injection` |
| MongoDB / `Document.parse` / `$where` / operator maps | `java-nosql-injection` |
| `DirContext` / LDAP filter / DN | `java-ldap-injection` |
| `XPath.compile` / `evaluate` | `java-xpath-injection` |
| `Runtime.exec` / `ProcessBuilder` / Commons Exec | `java-command-injection` |
| SpEL / `parseExpression` / `StandardEvaluationContext` | `java-spel-injection` |
| XXE / `DocumentBuilderFactory` / insecure XML features | `java-xxe` |

Also consult shared casebase and FP patterns under `.opencode/shared/security-audit/` for transferable lessons.

## Evidence Requirements

Trace source to sink, identify whether parameterization or allowlisting applies to the exact fragment, and state reachable impact. Prefer deep-pack Evidence Contract fields when that skill is loaded.
