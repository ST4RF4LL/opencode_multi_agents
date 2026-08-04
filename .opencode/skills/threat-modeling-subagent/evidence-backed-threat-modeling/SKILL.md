---
name: evidence-backed-threat-modeling
description: Build or refine a durable project threat model from code, Recon inventories, owner knowledge, security history, and explicit trust assumptions; then produce deterministic Focus Areas for Tri-Lens vulnerability discovery. Use before source, platform, or AI audits when entry points, assets, actors, trust boundaries, project-specific threat classes, or discovery partitions must be defined and covered.
---

# Evidence-Backed Threat Modeling

Read [references/artifact-schemas.md](references/artifact-schemas.md) before emitting either artifact.

## Build the model

1. Bind all outputs to the frozen `audit_id` and `scope_digest`. Start from `recon-summary.json` and the compact `threat-routing-index.json`; do not rerun coverage-accounting builders or ingest full manifests when the routing index is valid.
2. Derive system context, assets, actors, entry points, trust boundaries, controls, and deployment uncertainties from repository evidence.
3. Mine authorized history using stack-specific security terms in addition to `CVE`, `security`, `vuln`, `fix`, and `exploit`. Read relevant diffs; cluster evidence by `entry_point × weakness_class × asset`.
4. Generalize point vulnerabilities into durable outcome-oriented threats. A threat must survive the patching of any one instance.
5. Apply STRIDE to every application entry point. For infrastructure and IAM surfaces, also test over-grant, lateral identity, drift, residual access, excess data exposure, and automated-action scope enforcement.
6. Record current controls and residual likelihood. Keep every architecture,
   deployment, identity, data, dependency, operator, and external assumption in
   the typed `assumptions` array rather than hiding it inside a threat.
7. Define evidence-backed security invariants and their enforcement points.
   Express each threat as at least one ordered attacker story tied to an actor,
   entry point, asset, and concrete outcome.
8. Record explicitly excluded attacker stories, why they are outside the frozen
   scope, and the evidence change that would bring them back into scope.
9. Calibrate `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` against project-specific
   Java/Web outcomes. This prioritizes the threat model only; do not invent
   numeric severity or replace post-adjudication CVSS.
10. Cover every entry point with one or more threats or an explicit
    deprioritized decision. Preserve unresolved high-risk questions as blocking
    gaps.

Use provenance tags `code-verified`, `documented`, `owner-asserted`, `history-inferred`, `deployment-unknown`, and `contradictory`. Never promote an owner statement or old advisory into code-verified evidence.

For AI systems, include malicious content, compromised tools, peer agents, knowledge sources, model providers, tenants, supply-chain actors, and insiders where applicable. Bind AI threats to application assets and consequences rather than reporting model behavior alone.

## Refine with the owner

Use bootstrap open questions rather than restarting cold. Refine only when answers are already available or an interview pass was explicitly requested. Ask only questions that change exposure, actor capability, asset priority, control status, or risk acceptance. Preserve the original evidence and annotate corrected assumptions.

## Partition Focus Areas

Create Focus Areas around reachable entry points, protocols/formats, business workflows, identities/tenants, trust boundaries, sensitive assets, deployment transitions, and AI tool/RAG/memory/agent chains. Avoid directory-only partitions.

For each Focus Area:

- reference its entry points, threats, trust boundaries, assets, and history clusters;
- require `coverage` and `blind` discovery tracks;
- require `seeded-variant` when historical clusters or prior confirmed findings map to the area;
- assign each relevant base and AI owner exact file/function/catalog IDs;
- distinguish primary accounting assignments from overlapping context IDs.

Across all Focus Areas, every reviewable file/function/catalog entity must have exactly one primary assignment for its owner/domain. Create a residual area for unmapped entities. Never hide assignment gaps by duplicating IDs.

Seal both artifacts with `seal-semantic-manifest.mjs`, sealing the threat model
first and copying its digest into `focus-areas.json` before sealing the latter.
The sealer invokes `scripts/threat-model-contract.mjs`; a prose-complete but
contract-invalid threat model is not a valid phase output.
