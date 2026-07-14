# Shared Security Audit Assets

This directory is readable by all security audit subagents.

Only `security-skill-optimizer` should normally modify these assets during the validation feedback loop.

## Directories

- `joern-rules/`: Joern rules, rule metadata, and rule inventory.
  - Layout: `joern-rules/<language>/<rule-id>.sc` + `<rule-id>.md`, inventory in `index.json`.
  - Java seed: 45 rules promoted from `java-subagent` deep packs (`java-*-locate-sinks`, `source-to-sink`, derived SQLi patterns, …). Run via `joern_run_rule` with `language=java`.
- `vulnerability-cases/`: confirmed or likely reusable vulnerability cases.
  - Java seed: 21 cases under `vulnerability-cases/java/<skill>-case-*/` with `case-summary.json` plus defensive samples.
- `false-positive-cases/`: rejected findings and false-positive patterns.
  - Java seed: 8 pattern packs under `false-positive-cases/java/<skill>-fp.md|.yaml`.
- `rule-results/`: non-source static scan summaries used to improve rules and skills.

## Java Deep Skill Mapping

Deep packs live under `.opencode/skills/java-subagent/` and share assets here:

| Skill | Joern rule prefix | Case prefix |
|-------|-------------------|-------------|
| `java-sql-injection` | `java-sql-injection-*` | `java-sql-injection-case-*` |
| `java-nosql-injection` | `java-nosql-injection-*` | `java-nosql-injection-case-*` |
| `java-ldap-injection` | `java-ldap-injection-*` | `java-ldap-injection-case-*` |
| `java-xpath-injection` | `java-xpath-injection-*` | `java-xpath-injection-case-*` |
| `java-command-injection` | `java-command-injection-*` | `java-command-injection-case-*` |
| `java-xss` | `java-xss-*` | `java-xss-case-*` |
| `java-log-injection` | `java-log-injection-*` | `java-log-injection-case-*` |
| `java-weak-cryptography` | `java-weak-cryptography-*` | `java-weak-cryptography-case-*` |

## Feedback Flow

1. Source auditors produce candidate findings.
2. `vulnerability-validator` classifies them as `confirmed`, `likely`, `needs-info`, or `false-positive`.
3. `security-audit-orchestrator` sends useful learning signals to `security-skill-optimizer`.
4. `security-skill-optimizer` updates skills, Joern rules, vulnerability cases, and false-positive cases.
