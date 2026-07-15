# Java Subagent Skill Collection

This directory is the skill collection for `java-source-auditor`, not a single OpenCode skill.

OpenCode-discoverable skills are listed in `collection.json` and live under `.opencode/skills/java-subagent/<skill-name>/SKILL.md`.

## Skill Layers

| Layer | Skills | Role |
|-------|--------|------|
| Thin review | `java-deserialization-review`, `java-injection-review`, `java-web-security-review` | Fast coverage checklists for D1–D10 routing |
| Deep vuln packs | `java-sql-injection`, `java-nosql-injection`, `java-ldap-injection`, `java-xpath-injection`, `java-command-injection`, `java-spel-injection`, `java-xss`, `java-xxe`, `java-jwt-misuse`, `java-csrf`, `java-idor`, `java-deserialization`, `java-path-traversal`, `java-file-upload`, `java-ssrf`, `java-open-redirect`, `java-weak-cryptography`, `java-hardcoded-secrets`, `java-log-injection`, `java-mass-assignment` | Full progressive-load packs (models, rules, cases, validation, evidence) |

Deep packs were merged from `vuln_skill_builder/skills/java-*` and keep their internal layout:

```
<skill>/
  SKILL.md
  manifest.yaml
  scope/ models/ rules/ analysis/ cases/ validation/ evidence/ tests/
```

Shared promotions (used by Joern MCP + skill optimizer):

- Joern rules → `.opencode/shared/security-audit/joern-rules/java/<skill>-*.sc`
- Vulnerability cases → `.opencode/shared/security-audit/vulnerability-cases/java/<skill>-case-*`
- False-positive patterns → `.opencode/shared/security-audit/false-positive-cases/java/<skill>-fp.md`

## Deep pack → dimension map

| Skill | Dimension | Weakness |
|-------|-----------|----------|
| `java-sql-injection` | D1 | `sql-injection` |
| `java-nosql-injection` | D1 | `nosql-injection` |
| `java-ldap-injection` | D1 | `ldap-injection` |
| `java-xpath-injection` | D1 | `xpath-injection` |
| `java-command-injection` | D1 | `command-injection` |
| `java-spel-injection` | D1 | `spel-injection` |
| `java-xss` | D1 | `xss` |
| `java-xxe` | D1 | `xxe` |
| `java-jwt-misuse` | D2 | `jwt-misuse` |
| `java-csrf` | D2 | `csrf` |
| `java-idor` | D3 | `idor` |
| `java-deserialization` | D4 | `deserialization` |
| `java-path-traversal` | D5 | `path-traversal` |
| `java-file-upload` | D5 | `file-upload` |
| `java-ssrf` | D6 | `ssrf` |
| `java-open-redirect` | D6 | `open-redirect` |
| `java-weak-cryptography` | D7 | `weak-cryptography` |
| `java-hardcoded-secrets` | D8 | `hardcoded-secrets` |
| `java-log-injection` | D8 | `log-injection` |
| `java-mass-assignment` | D9 | `mass-assignment` |

## Adding a Java/JVM audit skill

1. Create `.opencode/skills/java-subagent/<skill-name>/SKILL.md`.
2. Use a permitted prefix such as `java-*`, `jvm-*`, `spring-security-*`, or `deserialization-*`.
3. Add the skill name to this collection's `collection.json`.
4. For deep packs, also publish Joern rules / cases under `.opencode/shared/security-audit/` and update the corresponding `index.json`.
5. Update `.opencode/agent-manifest/skill-map.json` only if the collection-to-agent mapping needs adjustment.
