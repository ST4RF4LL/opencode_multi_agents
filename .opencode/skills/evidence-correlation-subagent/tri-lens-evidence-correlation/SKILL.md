---
name: tri-lens-evidence-correlation
description: Deterministically normalize Focus-Area Tri-Lens coverage plus blind, seeded-variant, and system-chain evidence; deduplicate candidates, merge evidence facets, expose contradictions and gaps, and generate targeted follow-up packets after an audit round.
license: MIT
metadata:
  role: security-evidence-correlator
  collection: evidence-correlation-subagent
---

# Tri-Lens Evidence Correlation

Correlate existing evidence without performing new vulnerability discovery, inventing attack-chain transitions, or performing exploitability classification.

## Normalize Coverage

Use this unique cell key:

```text
scope | language | dimension | lens
focus_area_id | assignment_id | language/domain | dimension | lens
threat_id | lens
focus_area_id | discovery_track
```

Require all assigned D1-D10 cells for each session. Quarantine malformed or wrong-audit reports and emit a schema `GAP`.

Require sealed threat/Focus digests, `focus_area_id`, and `discovery_track=coverage` on accounting reports. Consume `blind` and `seeded-variant` discovery artifacts as candidate evidence only; they never close file/function/catalog or D1-D10 records. Consume the attack-chain hunter report as the only source of new system-chain candidates.

Also preserve these exact accounting keys without aggregation:

```text
file_id | domain(base|ai) | lens | round | owner_agent
function_id | domain(base|ai) | lens | round | owner_agent
catalog_id | domain | lens | round | owner_agent
```

Compare each report's coverage arrays with its assigned ID arrays. Do not synthesize a missing row, copy base conclusions into the AI overlay or one catalog domain into another, or treat an earlier round as superseded unless a later report explicitly carries that same entity/domain/lens key.

When multiple reports contribute to a cell:

1. Use `GAP` if any assigned target or required artifact remains unreviewed.
2. Otherwise use `FINDING` if one or more candidates remain.
3. Otherwise use `PASS` if applicable targets were completely reviewed.
4. Use `N/A` only if all contributions prove inapplicability.

Keep findings separate from completeness so a `GAP` cell can still reference discovered finding IDs.

## Fingerprint Findings

Build a stable fingerprint from normalized:

```text
dimension + component + weakness + primary location/operation + entry/anchor identity
```

Do not merge solely because titles are similar. Merge only when evidence points to the same vulnerable condition. Preserve every source agent, session, raw finding ID, and evidence facet.

## Canonical Finding

Use this structure:

```json
{
  "canonical_id": "AUDIT-D6-001",
  "dimension": "D6",
  "origin_lenses": ["sink-driven", "control-driven", "config-driven"],
  "source_findings": [],
  "locations": [],
  "sink_evidence": [],
  "control_evidence": [],
  "config_evidence": [],
  "mitigating_evidence": [],
  "contradictions": [],
  "residual_uncertainty": [],
  "validation_state": "unvalidated"
}
```

A lens may provide mitigation rather than vulnerability evidence. Do not require all three lenses to agree before forwarding a candidate.

## Contradictions

Record incompatible statements such as:

- a control reported absent while another report identifies an inherited/global control
- a dangerous default reported active while an environment override disables it
- a reachable anchor reported dead or test-only elsewhere
- incompatible target counts or scopes

Include both evidence references and a specific resolution question. Do not choose a winner without evidence.

## Follow-Up Packets

Create minimal work packets for:

- missing or invalid file/function/catalog domain-and-lens records
- incomplete cells
- contradictions that affect severity or validity
- unbounded inventories
- high-risk runtime/environment uncertainty
- missing entry-point threat decisions, threat-lens sessions, Focus Area assignments/tracks, or attack-chain surface reviews

Keep the original `audit_strategy`; do not ask one session to resolve multiple lenses. Include exact files, inventory IDs, prior evidence, and the question to resolve.

## Output Schema

The correlation JSON must include:

```yaml
schema_version: 1
audit_id: <id>
round: <n>
consumed_artifacts: []
rejected_artifacts: []
coverage_cells: []
semantic_coverage_cells: []
dimension_summary: []
canonical_findings: []
duplicate_map: []
contradictions: []
residual_gaps: []
file_coverage_records: []
function_coverage_records: []
catalog_coverage_records: []
attack_chain_candidates: []
discovery_artifacts: []
discovery_metrics:
  agent_runs: 0
  raw_findings: 0
  unique_canonical_findings: 0
  duplicate_rate: 0
  novelty_yield: 0
  new_surface_rate: 0
follow_up_packets: []
```

Do not change validation state beyond `unvalidated` unless consuming an explicit validator decision.

Treat discovery metrics as routing signals, not completeness proof. When duplicate rate rises and novelty/new-surface yield falls, recommend repartitioning Focus Areas, a blind pass, or a system-chain pass instead of adding identical agents.
