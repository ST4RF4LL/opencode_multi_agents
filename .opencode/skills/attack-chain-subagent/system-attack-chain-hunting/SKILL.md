---
name: system-attack-chain-hunting
description: Hunt cross-module and cross-trust-boundary attack chains after Focus Area Tri-Lens, blind, and seeded-variant discovery finishes. Use when partition findings must be recombined into system-level hypotheses and every Focus Area, trust boundary, and asset must receive an explicit chain-review state.
---

# System Attack-Chain Hunting

## Inputs

Require the sealed threat model, sealed Focus Areas, Recon inventories, all `coverage` audit reports, all `blind` and required `seeded-variant` discovery reports, source/config evidence, the validated Finding Adjudication manifest, and prior chain gaps for the current audit and round. Only `SUPPORTED_STATIC` and `SUPPORTED_RUNTIME` adjudication decisions may appear in `evidence_refs`.

## Search

1. Review every Focus Area, trust boundary, and asset; initialize each as `GAP` before analysis.
2. Connect evidence only when a prior step's postcondition satisfies the next step's precondition.
3. Search across identities, tenants, components, protocols, storage, deployment layers, and AI agent/tool/RAG/memory boundaries.
4. Prioritize combinations of adjudicated signals that reach a high/critical asset.
5. Check alternate entry points and control/config assumptions that permit a chain to bypass a local mitigation.
6. Keep unsupported runtime or deployed transitions as explicit gaps. A deployment-unknown or unresolved step makes the chain `CONDITIONAL`; a contradicted step makes it `CONTRADICTED`.

Useful chain families include information leak to credential use, configuration exposure to missing control to dangerous sink, upload to extraction to executable loading, cross-tenant cache to object access, and prompt injection to delegated tool action.

## Output

Write one JSON object with:

```json
{
  "schema_version": 2,
  "audit_id": "audit-id",
  "round": 1,
  "agent_name": "security-attack-chain-hunter",
  "scope_digest": "sha256",
  "threat_model_digest": "sha256",
  "focus_areas_digest": "sha256",
  "adjudication_manifest_digest": "sha256",
  "chains": [{
    "chain_id": "CHAIN-001",
    "assessment_state": "CONDITIONAL",
    "steps": [{"step_id":"S1","claim":"...","evidence_state":"DEPLOYMENT_UNKNOWN","evidence_refs":[],"blocking_gap_ids":["GAP-CHAIN-001-S1"]}],
    "transitions": [],
    "first_blocking_step_id": "S1"
  }],
  "gaps": [{"gap_id":"GAP-CHAIN-001-S1","chain_ids":["CHAIN-001"]}],
  "chain_accounting": {"raw_chain_ids":["CHAIN-001"],"accepted_chain_ids":["CHAIN-001"],"rejected_chain_ids":[]}
}
```

Run `validate-attack-chains.mjs --adjudication <manifest> --chains <report>` before handing the artifact to correlation. The accounting IDs must conserve every raw chain as either accepted (`CONDITIONAL`/`SUPPORTED_*`) or explicitly `CONTRADICTED`. A conditional chain is not a supported exploit path and must retain its first blocking step and bidirectional gap reference.
