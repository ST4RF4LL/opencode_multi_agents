# Shared Security Audit Assets

This directory is readable by all security audit subagents.

Only `security-skill-optimizer` should normally modify these assets during the validation feedback loop.

The audit profile is Java/Web-first: Java/JVM services, Java Web frameworks,
browser code, JSP/templates, and their authentication, authorization, data,
framework, and deployment boundaries receive the primary technical model.
Platform, Python, C/C++, and AI agents remain available only when the frozen
repository scope contains those surfaces; their presence does not broaden the
default target profile.

## Directories

- `catalogs/`: versioned coverage catalogs. `application-ai-vulnerability-catalog.json` maps application, platform, and AI-system risks to D1-D10, authoritative baselines, applicable domains, and all three lens questions.
  - AI-agent controls incorporate the OWASP AI Agent Security Cheat Sheet, including exact-action approval integrity, multi-agent message security, AI-console configuration safety, and adversarial release gates.
- `joern-rules/`: Joern rules, rule metadata, and rule inventory.
  - Layout: `joern-rules/<language>/<rule-id>.sc` + `<rule-id>.md`, inventory in `index.json`.
  - Java seed: 105 rules promoted from `java-subagent` deep packs (`java-*-locate-sinks`, `source-to-sink`, derived SQLi patterns, …). Build a CPG with `joern-parse`, then run a rule with `joern <cpg.bin> --script <rule.sc>`.
- `vulnerability-cases/`: confirmed or likely reusable vulnerability cases.
  - Java seed: 21 cases under `vulnerability-cases/java/<skill>-case-*/` with `case-summary.json` plus defensive samples.
- `false-positive-cases/`: rejected findings and false-positive patterns.
  - Java seed: 8 pattern packs under `false-positive-cases/java/<skill>-fp.md|.yaml`.
- `adjudication-regressions/`: paired semantic-decision fixtures. `mall-v1-semantic-twins.json` fixes the evidence boundary and expected adjudication for JWT, object storage, logging, mass assignment, Spring RBAC, Actuator, CORS, and URL/SSRF/redirect claims, plus the three historical overclaimed attack chains.
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

1. `security-intel-collector` freezes a Git-aware file scope, builds digest-cached function manifests, builds and verifies a frozen external-interface anchor universe, emits a compact threat-routing index, and produces entry-point, sink, sensitive-operation, config-surface, and AI-surface inventories. Literal framework/spec declarations remain `CONFIRMED`; executable/configuration anchors remain `CANDIDATE`; extractor uncertainty blocks complete claims.
2. `security-threat-modeler` performs one bounded bootstrap by default from the compact routing index and Recon artifacts, optionally refines only when owner answers are already available, closes entry-point threat decisions, generalizes authorized history, and partitions primary base/AI assignments into sealed Focus Areas.
3. The orchestrator validates catalog v2, freezes a sparse Focus-Area-bound Coverage Plan, and initializes one local task per `Focus Area × domain`. Source, platform, and AI auditors receive only bounded work packets; all Tri-Lens work stays inside the packet and each specialist writes a report plus a DONE/GAP handoff. The orchestrator validates handoff structure and report existence only, then records state locally. It does not use OpenCode todolist, a coverage MCP, receipts, tokens, or hash chains. Blind and history/case-seeded `seeded-variant` discovery remain checklist-light and risk-driven.
4. `security-attack-chain-hunter` performs a new system-level pass across every Focus Area, trust boundary, and asset.
5. `security-evidence-correlator` preserves structural/semantic accounting, merges cross-track evidence, deduplicates candidates, and canonicalizes supplied attack chains.
6. `security-audit-orchestrator` retains structural file/function accounting, verifies semantic coverage, and requires a terminal local task summary with valid packet handoffs plus a Chinese final report. `GAP` remains visible; a completed task is not a claim that every vulnerability type was independently proven absent.
7. `vulnerability-validator` runs the local Affirmative/Negative/Moderator chain before final report sealing and writes digest-bound review companions.
8. `security-audit-orchestrator` sends completed review learning signals to `security-skill-optimizer`, which updates skills, rules, and cases with threat/Focus/dimension/lens/track tags. Incomplete reviews cannot promote candidates as confirmed cases.
