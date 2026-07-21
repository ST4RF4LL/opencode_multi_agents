# Shared Security Audit Assets

This directory is readable by all security audit subagents.

Only `security-skill-optimizer` should normally modify these assets during the validation feedback loop.

## Directories

- `catalogs/`: versioned coverage catalogs. `application-ai-vulnerability-catalog.json` maps application, platform, and AI-system risks to D1-D10, authoritative baselines, applicable domains, and all three lens questions.
  - AI-agent controls incorporate the OWASP AI Agent Security Cheat Sheet, including exact-action approval integrity, multi-agent message security, AI-console configuration safety, and adversarial release gates.
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

1. `security-intel-collector` freezes the recursive file scope, builds complete function manifests, and produces entry-point, sink, sensitive-operation, config-surface, and AI-surface inventories.
2. `security-threat-modeler` bootstraps and optionally owner-refines durable threats, closes entry-point threat decisions, generalizes authorized history, and partitions primary base/AI assignments into sealed Focus Areas.
3. Source, platform, and AI auditors run Focus Area `coverage` sessions under each Tri-Lens strategy plus checklist-light `blind` and history/case-seeded `seeded-variant` discovery where required.
4. `security-attack-chain-hunter` performs a new system-level pass across every Focus Area, trust boundary, and asset.
5. `security-evidence-correlator` preserves structural/semantic accounting, merges cross-track evidence, deduplicates candidates, and canonicalizes supplied attack chains.
6. `security-audit-orchestrator` runs both deterministic verifiers and writes the complete final report; only two `complete: true` artifacts authorize complete structural-and-semantic accounting statements.
7. `vulnerability-validator` submits that sealed report once to vuln-judger with `engine=opencode`, monitors the Affirmative/Negative/Moderator run, and writes digest-bound review companions.
8. `security-audit-orchestrator` sends completed review learning signals to `security-skill-optimizer`, which updates skills, rules, and cases with threat/Focus/dimension/lens/track tags. Incomplete reviews cannot promote candidates as confirmed cases.
