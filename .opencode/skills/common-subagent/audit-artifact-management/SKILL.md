---
name: audit-artifact-management
description: Manage threat-led Focus Area Tri-Lens artifacts, including sealed threat/Focus manifests, coverage and discovery JSON, system attack-chain reports, SARIF, correlation, dual coverage verification, and scoped tmp cleanup/promotion rules.
license: MIT
metadata:
  role: shared
  phase: artifact-management
---

# Audit Artifact Management

Use this skill whenever an audit agent creates temporary files, tool reports, static-analysis output, vulnerability-mining output, scripts, or rules.

## Required Paths

Use `.opencode/agent-manifest/artifact-policy.json` as the source of truth.

- Static-analysis report: `reports/sarif/<agent-name>.<agent-session-id>.sarif`
- Vulnerability-mining report: `reports/vulnerability-mining/<agent-name>.<agent-session-id>.audit-report.json`
- Blind/seeded discovery report: `reports/vulnerability-mining/<agent-name>.<agent-session-id>.discovery.json`
- System attack-chain report: `reports/attack-chains/security-attack-chain-hunter.<audit-id>.r<round>.json`
- Correlation report: `reports/correlation/security-evidence-correlator.<audit-id>.r<round>.json`
- Final accounting verification: `reports/coverage/coverage-verification.<audit-id>.json`
- Final semantic verification: `reports/coverage/semantic-coverage-verification.<audit-id>.json`
- Durable verification inputs: `reports/coverage/<audit-id>/inputs/`
- Recon and scratch workspace: `tmp/<audit-id>/`

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

Store `entry-points.json`, `sinks.json`, `sensitive-operations.json`, `config-surfaces.json`, `ai-surfaces.json`, and `recon-summary.json` under `tmp/<audit-id>/recon/`. Store sealed `threat-model.json` and `focus-areas.json` beside them. Store the frozen scope and complete function manifests under `tmp/<audit-id>/recon/coverage/`. These are intermediate planning inputs and may be cleaned only after correlation, verification, and final reporting consume them.

## Discovery and Attack Chains

Blind and seeded-variant sessions write `*.discovery.json` and cannot close accounting coverage. The system attack-chain hunter writes one durable report per round and accounts for every Focus Area, trust boundary, and asset.

## Correlation Reports

One audit round produces one correlation JSON. Include consumed/rejected artifacts, normalized structural and semantic coverage cells, discovery artifacts, dimension summaries, canonical findings, duplicate mappings, contradictions, residual gaps, canonicalized attack-chain candidates, and follow-up packets.

## Coverage Verification

After the last correlation/gap round, the orchestrator snapshots the validated scope, function manifests, catalog, sealed threat model, and sealed Focus Areas under `reports/coverage/<audit-id>/inputs/`. Run both structural and semantic verifiers. Preserve the snapshot index and both final artifacts; do not copy a failed artifact into a report that claims completion.

## Cleanup and Promotion

The orchestrator cleans only the current `tmp/<audit-id>/` directory at task end after it has consumed recon/session/correlation reports and after `security-skill-optimizer` has promoted reusable scripts, rules, or cases. Do not store durable audit knowledge only in `tmp/`.
