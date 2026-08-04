---
name: audit-artifact-management
description: Manage threat-led Focus Area Tri-Lens artifacts, including sealed threat/Focus manifests, coverage and discovery JSON, system attack-chain reports, SARIF, correlation, dual coverage verification, final-report-bound third-party review companions, durable reports/ deliverables, and manual-only tmp retention/promotion rules.
license: MIT
metadata:
  role: shared
  phase: artifact-management
---

# Audit Artifact Management

Use this skill whenever an audit agent creates temporary files, tool reports, static-analysis output, vulnerability-mining output, scripts, or rules.

## Required Paths

Use `.opencode/agent-manifest/artifact-policy.json` as the source of truth.

All durable deliverables go under workspace-root `reports/` only. Never write final reports under `tmp/` or inside audited application/test source trees outside `reports/`.

- Final human-readable audit report: `reports/final/security-audit-report.<audit-id>.md`
- Static-analysis report: `reports/sarif/<agent-name>.<agent-session-id>.sarif`
- Vulnerability-mining report: `reports/vulnerability-mining/<agent-name>.<agent-session-id>.audit-report.json`
- Blind/seeded discovery report: `reports/vulnerability-mining/<agent-name>.<agent-session-id>.discovery.json`
- System attack-chain report: `reports/attack-chains/security-attack-chain-hunter.<audit-id>.r<round>.json`
- Correlation report: `reports/correlation/security-evidence-correlator.<audit-id>.r<round>.json`
- Final accounting verification: `reports/coverage/coverage-verification.<audit-id>.json`
- Final semantic verification: `reports/coverage/semantic-coverage-verification.<audit-id>.json`
- Durable verification inputs: `reports/coverage/<audit-id>/inputs/`
- OpenCode three-party review JSON: `reports/validation/vuln-judger-review.<audit-id>.json`
- OpenCode three-party review Markdown: `reports/validation/vuln-judger-review.<audit-id>.md`
- Stage/Agent handoff envelopes:
  `reports/handoffs/<audit-id>/<stage-id>/<agent>.<session>.input|output.json`
- Stage handoff verification:
  `reports/handoffs/stage-handoff-verification.<audit-id>.r<round>.json`
- External runtime-validation requests/results:
  `reports/validation-handoff/runtime/<audit-id>/<finding-id>.request|result.json`
- Recon and scratch workspace: `tmp/<audit-id>/`

## Fixed Stage/Agent Contracts

Use `contracts/stage-agent-contracts.json` as the only stage/agent template
registry. It defines every internal stage, all 14 agents, 25 invocation
contracts, the exact required/optional artifact types, and the exact
required/optional payload fields for each input and output.
See `references/stage-agent-io.md` for the exact common envelope shapes.

Every invocation has two durable envelopes:

1. The orchestrator writes an `INPUT` envelope, seals it with
   `scripts/seal-stage-agent-envelope.mjs`, and dispatches that exact digest.
2. The invoked agent writes a matching `OUTPUT` envelope whose
   `input_envelope_digest` equals the input digest.

Use `scripts/validate-stage-agent-envelope.mjs` before consuming an envelope.
`COMPLETE` requires every required output artifact binding and an empty `gaps`
array. Every other status requires structured gaps and cannot be interpreted as
phase completion.

Before final synthesis, run `scripts/verify-stage-agent-handoffs.mjs`. It
derives coverage expectations for every sealed Focus Area assignment × lens and
every required blind/seeded discovery track. A missing output envelope is a
missing execution, even if an agent response says it finished. This handoff
gate supplements rather than replaces structural and semantic coverage gates.

## Static Analysis Reports

One agent session produces one SARIF file. If several static tools are used in the same session, merge their results into that session's SARIF file using multiple `runs`.

Use SARIF 2.1.0. At minimum include:

- `version`
- `$schema`
- `runs[].tool.driver.name`
- `runs[].results[]`
- `runs[].results[].ruleId`
- `runs[].results[].message.text`
- `runs[].results[].locations[].physicalLocation.artifactLocation.uri`

## Vulnerability-Mining Reports

One vulnerability-mining agent session produces one JSON file. At minimum include:

- `schema_version`
- `audit_id`
- `round`
- `agent_name`
- `agent_session_id`
- `focus_area_id`
- `discovery_track=coverage`
- `scope`
- `language`
- `audit_strategy` (exactly one of `sink-driven`, `control-driven`, `config-driven`)
- `dimensions`
- `tool_inputs`
- `coverage_cells` (one per requested dimension for the assigned lens)
- `review_depth` (actual files/functions/path expansions/searches; anomaly signal only)
- `file_coverage` (one per assigned file ID, with explicit `domain=base|ai`)
- `function_coverage` (one per assigned function ID, with explicit `domain=base|ai`)
- `catalog_coverage` (one per applicable catalog ID and active domain)
- `findings`
- `artifacts`
- `learning_candidates`

## Recon Inventories

Store `entry-points.json`, `sinks.json`, `sensitive-operations.json`, `config-surfaces.json`, `ai-surfaces.json`, and `recon-summary.json` under `tmp/<audit-id>/recon/`. Store sealed `threat-model.json` and `focus-areas.json` beside them. Store the frozen scope and complete function manifests under `tmp/<audit-id>/recon/coverage/`. These are intermediate planning inputs. Snapshot durable copies into `reports/coverage/<audit-id>/inputs/` before final verification. Do not treat `tmp/` as the only copy of anything that must survive review.

## Discovery and Attack Chains

Blind and seeded-variant sessions write `*.discovery.json` under `reports/vulnerability-mining/` and cannot close accounting coverage. The system attack-chain hunter writes one durable report per round under `reports/attack-chains/` and accounts for every Focus Area, trust boundary, and asset.

## Correlation Reports

One audit round produces one correlation JSON under `reports/correlation/`. Include consumed/rejected artifacts, normalized structural and semantic coverage cells, discovery artifacts, dimension summaries, canonical findings, duplicate mappings, contradictions, residual gaps, canonicalized attack-chain candidates, and follow-up packets.

## Coverage Verification

After the last correlation/gap round, the orchestrator snapshots the validated scope, function manifests, catalog, sealed threat model, and sealed Focus Areas under `reports/coverage/<audit-id>/inputs/`. Run both structural and semantic verifiers. Preserve the snapshot index and both final artifacts; do not copy a failed artifact into a report that claims completion.

## Final Report and Independent Review

Require a complete stage-handoff verification and both coverage gates before
building the deterministic final report model. The model must preserve the
fixed Finding v2 `attack_surface` block and its adjudication-input source
pointer for every finding.

Write the complete human-readable audit report first. After the handoff and
both coverage gates have emitted durable artifacts, compute the report SHA-256
and submit that exact report once to vuln-judger with `engine=opencode`. Keep
the reviewed report immutable.

Persist the structured and Markdown review exports under `reports/validation/`. Each companion must record the report path and SHA-256, vuln-judger run id and terminal state, three-party role results, finding accounting, disagreements, and residual gaps. A partial, failed, stopped, or digest-invalidated run remains an explicit review gap and never authorizes an independently-reviewed claim.

## External Runtime-Validation Handoff

This project does not execute runtime validation. When static adjudication
needs a later Java/Web runtime check, export
`external-runtime-validation-request-v1` with the shared
`finding-evidence-contract` builder/validator. The request binds the immutable
finding object, source location, adjudication decision, attack-surface facts,
proof gap, and isolated-test-only policy.

A downstream project may return
`external-runtime-validation-result-v1`. Validate it against the exact request
digest. The result must attest that it did not contact production or third-party
targets, use real credentials, persist, or perform destructive actions. Do not
auto-promote a returned outcome into this project's adjudication or final
report; that import belongs to the later project.
See `references/external-runtime-validation-handoff.md` for the producer and
consumer boundary.

## Retention and Promotion (No Auto tmp Cleanup)

- Write the final human-readable report only to `reports/final/security-audit-report.<audit-id>.md`.
- Agents must **not** automatically delete `tmp/` or `tmp/<audit_id>/`. Cleanup is manual-only after a human confirms durable `reports/**` deliverables are retained.
- `security-skill-optimizer` must still promote reusable scripts, rules, or cases out of `tmp/` into `.opencode/skills/` or `.opencode/shared/security-audit/`.
- Do not store durable audit knowledge only in `tmp/`.
