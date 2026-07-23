---
name: system-attack-chain-hunting
description: Hunt cross-module and cross-trust-boundary attack chains after Focus Area Tri-Lens, blind, and seeded-variant discovery finishes. Use when partition findings must be recombined into system-level hypotheses and every Focus Area, trust boundary, and asset must receive an explicit chain-review state.
---

# System Attack-Chain Hunting

## Inputs

Require the sealed threat model, sealed Focus Areas, Recon inventories, all `coverage` audit reports, all `blind` and required `seeded-variant` discovery reports, source/config evidence, and prior chain gaps for the current audit and round.

## Search

1. Review every Focus Area, trust boundary, and asset; initialize each as `GAP` before analysis.
2. Connect evidence only when a prior step's postcondition satisfies the next step's precondition.
3. Search across identities, tenants, components, protocols, storage, deployment layers, and AI agent/tool/RAG/memory boundaries.
4. Prioritize combinations of individually low/medium signals that reach a high/critical asset.
5. Check alternate entry points and control/config assumptions that permit a chain to bypass a local mitigation.
6. Keep unsupported runtime or deployed transitions as explicit gaps.

Useful chain families include information leak to credential use, configuration exposure to missing control to dangerous sink, upload to extraction to executable loading, cross-tenant cache to object access, and prompt injection to delegated tool action.

## Output

Write one JSON object with:

```json
{
  "schema_version": 1,
  "audit_id": "audit-id",
  "round": 1,
  "agent_name": "security-attack-chain-hunter",
  "scope_digest": "sha256",
  "threat_model_digest": "sha256",
  "focus_areas_digest": "sha256",
  "status": "PASS|FINDING|GAP",
  "reviewed_focus_area_ids": [],
  "reviewed_trust_boundary_ids": [],
  "reviewed_asset_ids": [],
  "evidence": [],
  "chain_candidates": [{"chain_id":"CHAIN-001","threat_ids":[],"focus_area_ids":[],"asset_ids":[],"preconditions":[],"transitions":[],"evidence":[],"residual_uncertainty":[]}],
  "gaps": []
}
```

Use `PASS` only when all required semantic IDs were reviewed and no gap remains. Use `FINDING` when that coverage is closed and chain candidates exist. A candidate is not a validated vulnerability.
