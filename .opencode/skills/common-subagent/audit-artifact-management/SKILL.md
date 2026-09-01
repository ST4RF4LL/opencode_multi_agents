---
name: audit-artifact-management
description: Manage threat-led Focus Area Tri-Lens artifacts, including enforced eight-stage deliveries, sealed threat/Focus manifests, coverage and discovery JSON, local finding truth-validation routing, system attack-chain reports, SARIF, deterministic final reports, and manual-only tmp retention/promotion rules.
license: MIT
metadata:
  role: shared
  phase: artifact-management
---

# Audit Artifact Management

Use this skill whenever an audit agent creates temporary files, tool reports, static-analysis output, vulnerability-mining output, scripts, or rules.

## Required Paths

Use `.opencode/agent-manifest/artifact-policy.json` as the source of truth.

The entry task injects the only durable-delivery and temporary roots. Do not choose a root from this skill; the `reports/` and `tmp/` examples below are compatibility-relative suffixes mapped by that entry task. Never write durable deliverables into the temporary or audited application/test source tree.

- Final human-readable audit report: `reports/final/security-audit-report.<audit-id>.md`
- Static-analysis report: `reports/sarif/<agent-name>.<agent-session-id>.sarif`
- Vulnerability-mining report: `reports/vulnerability-mining/<agent-name>.<agent-session-id>.audit-report.json`
- Blind/seeded discovery report: `reports/vulnerability-mining/<agent-name>.<agent-session-id>.discovery.json`
- System attack-chain report: `reports/attack-chains/security-attack-chain-hunter.<audit-id>.r<round>.json`
- Correlation report: `reports/correlation/security-evidence-correlator.<audit-id>.r<round>.json`
- Final accounting verification: `reports/coverage/coverage-verification.<audit-id>.json`
- Final semantic verification: `reports/coverage/semantic-coverage-verification.<audit-id>.json`
- Durable verification inputs: `reports/coverage/<audit-id>/inputs/`
- Finding truth-validation intake/quick/routing: `reports/validation/{truth-validation-intake,validation-routing}.<audit-id>.r<round>.json` and `reports/validation/quick/<audit-id>.r<round>.json`
- Local three-party static reviews: `reports/validation/static/<audit-id>/{affirmative,negative,moderator}.r<round>.json`
- Stage/Agent handoff envelopes:
  `reports/handoffs/<audit-id>/<stage-id>/<agent>.<session>.input|output.json`
- Stage handoff verification:
  `reports/handoffs/stage-handoff-verification.<audit-id>.r<round>.json`
- External runtime-validation requests/results:
  `reports/validation-handoff/runtime/<audit-id>/<finding-id>.request|result.json`
- Recon and scratch workspace: `tmp/<audit-id>/`

## Fixed Stage/Agent Contracts

Use `contracts/stage-agent-contracts.json` as the only stage/agent template
registry. It defines every internal stage and agent invocation contract, the exact required/optional artifact types, and the exact
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

## Fixed Workbench Stage Deliveries

Use `contracts/workbench-stage-deliveries.json` as the normative aggregation
registry for the eight workbench stages. It does not replace the P00-P10
Stage/Agent contracts: each workbench stage binds one or more internal stages,
their exact contract IDs, durable input/output artifact templates, validators,
completion gate, and recovery anchors.

Every completed workbench stage writes one digest-bound manifest to:

`reports/stage-deliveries/<audit_id>/<stage_id>.r<round>.json`

The manifest follows `contracts/stage-delivery-manifest-v1.schema.json`. Artifact
sets such as Focus audit results, findings, SARIF, follow-up packets, and runtime
validation requests/results use
`contracts/artifact-set-index-v1.schema.json`; an empty set remains an explicit
`item_count=0` deliverable rather than an omitted file.
Build or update each index with exact member paths and SHA-256 values, then run
`scripts/seal-artifact-set-index.mjs`. Stage materialization recomputes
`set_digest`, checks `item_count`, and verifies every indexed member is a regular
file with the declared digest.

Create manifests only through `scripts/seal-stage-delivery.mjs`; it reads a
request under `tmp/<audit_id>/`, computes file SHA-256, binds actual predecessor
files, seals the manifest, and immediately performs materialized validation.
Run `scripts/verify-stage-deliveries.mjs --audit-id <audit_id>` before recovery
and before task exit.

`scripts/validate-stage-delivery.mjs` checks the JSON contract, while
materialized verification additionally requires every bound file to exist as a
regular file under the controlled reports root, match its SHA-256, preserve
input provenance from predecessor outputs, and provide materialized evidence
for every PASS validator result.
`COMPLETE` requires every required or activated-conditional output, every
required or activated-conditional validator to pass, all forward predecessor
manifests to be `COMPLETE`, every feedback predecessor to use its edge-approved
status, a frozen scope binding, and zero gaps. Correlation
may create a new-round feedback edge to audit when
`correlation_gap_round` is active. The registry is `ACTIVE` + `ENFORCED` for new
workbench tasks: a zero exit code is converted to a recoverable interruption if
any of the eight materialized stages is incomplete. Historical artifact-only
tasks remain visible through a labeled legacy heuristic and are not silently
upgraded to compliant.

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

## Finding Truth Validation and Final Report

After preliminary adjudication and before CVSS, final attack chains, or report
generation, require the six-artifact finding truth-validation bundle. A task
that explicitly enabled test-environment context may run one loopback-only
quick batch for at most 120 seconds. A disabled task writes explicit SKIPPED
results. Every non-CONFIRMED item then passes through distinct local
Affirmative, Negative, and Moderator sessions.

`validation-routing` is the terminal finding source: `TRUE_POSITIVE` enters the
vulnerability list, `FALSE_POSITIVE` enters exclusions, and `INCONCLUSIVE`
enters residual gaps. CVSS and final attack chains consume only true positives.
Require a complete stage-handoff verification, truth-validation bundle, and
both coverage gates before building the deterministic final report model. Keep
the final report immutable after byte verification.

## External Runtime-Validation Handoff

When static adjudication needs Java/Web runtime evidence, export
`external-runtime-validation-request-v1` with the shared
`finding-evidence-contract` builder/validator. The request binds the immutable
finding object, source location, adjudication decision, attack-surface facts,
proof gap, and isolated-test-only policy.

The task-gated quick router may consume eligible requests only when the user
enabled a digest-valid test-environment context at task creation. It never runs
for more than 120 seconds in total, never contacts non-loopback targets, and
sends every non-confirmed result to local static review.

A separately authorized downstream project may return
`external-runtime-validation-result-v1`. Validate it against the exact request
digest. The result must attest that it did not contact production or third-party
targets, use real credentials, persist, or perform destructive actions. Do not
auto-promote a returned outcome into this project's adjudication or final
report; that import belongs to the later project.

On a separate explicit manual workbench request, this workspace may invoke
`dynamic-vulnerability-validator` for catalog types whose `applies_to` includes
`web` against a user-supplied loopback application. It uses Chrome DevTools MCP,
two distinct test accounts, non-destructive proof, and a sanitized target binding.
`JW-INJECT-06` retains its bounded stored-marker and specialized result contract.
This full-validation sidecar is not part of the eight-stage gate and has the
same non-promotion boundary. Credential values remain in the private task
context/session and never enter a durable artifact.
See `references/external-runtime-validation-handoff.md` for the producer and
consumer boundary.

## Retention and Promotion (No Auto tmp Cleanup)

- Write the final human-readable report only to `reports/final/security-audit-report.<audit-id>.md`.
- Agents must **not** automatically delete `tmp/` or `tmp/<audit_id>/`. Cleanup is manual-only after a human confirms durable `reports/**` deliverables are retained.
- `security-skill-optimizer` must still promote reusable scripts, rules, or cases out of `tmp/` into `.opencode/skills/` or `.opencode/shared/security-audit/`.
- Do not store durable audit knowledge only in `tmp/`.
