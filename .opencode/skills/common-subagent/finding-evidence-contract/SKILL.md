---
name: finding-evidence-contract
description: Validate and bind security finding artifacts before they enter coverage accounting, correlation, or a final audit report. Use when a source-audit agent emits a candidate finding, when a completed local packet report is handed off, or when a verifier must reject incomplete, misclassified, or unproven finding evidence.
---

# Finding Evidence Contract

Create a standalone JSON object conforming to `schemas/finding-v2.schema.json` for each candidate. Keep the mined conclusion at `CANDIDATE`; only an independent adjudication artifact may promote it.

Run `scripts/validate-finding-artifact.mjs` before placing a coverage-track FINDING in a packet-backed report. Bind the candidate to its audit, frozen scope, primary check, Focus Area, domain, lens, vulnerability type, and explicitly claimed dimensions.

Every candidate must contain a concrete primary location, typed evidence facts,
reachability and attacker-influence assessments, the fixed
`attack_surface.schema_version=1` fact block, examined guards, uncertainty,
severity rationale, remediation, and source-report provenance. Do not use a
free-text finding ID occurrence as evidence.

All human-facing finding prose must be written in Chinese: title, evidence
`claim`, rationale, uncertainty, guard description, severity rationale, and
remediation summary. Keep only identifiers, paths, API names, code snippets,
and catalog IDs in their original form. This applies equally to JSON evidence
artifacts and the final Markdown report, so the workbench can present a
directly readable finding ledger without machine translation.

The attack-surface block is not prose metadata. It records, with indexes into
`evidence.facts`, all of the following:

- in-scope decision, exposure, attack vector, and authentication scope
- explicit preconditions and attacker/victim/effective identities
- trust-boundary crossing and impact outcome
- target reach (single object, tenant, cross-tenant, fleet, and so on)
- examined controls, counterevidence, blind spots, and confidence

Core non-unknown assessments require evidence indexes. Controls and
counterevidence keep their own evidence references, so an adjudicator and the
final report can preserve limiting facts instead of restating only the positive
claim. `validateAttackSurface` is exported for report and handoff contracts;
do not define a weaker copy elsewhere.

Candidate severity is qualitative. It may include only a `PROVISIONAL` CVSS 3.1
vector with no number or rating; `score`, `base_score`, `rating`, and final
CVSS fields are rejected. Only the post-adjudication CVSS assessment builder
derives a final score and severity.

For coverage-track findings, `classification.discovery_track` is `coverage`, `routing.primary_check_id` identifies the Plan check used for routing, and `classification.dimension_claims` must be a subset of that check's dimensions. Blind and seeded findings remain candidates and never close coverage checks.

Use `scripts/finding-contract.mjs` as the shared implementation. Verifiers and local packet workflows must call the same functions rather than duplicating field checks.

## External runtime-validation handoff

Use `scripts/external-runtime-validation-contract.mjs` only to export or verify
a handoff to a separately authorized project. A request binds:

- the canonical Finding v2 object digest and frozen source location
- the independent static/inconclusive adjudication decision
- the exact `attack_surface` facts and source/sink evidence indexes
- the runtime proof gap and an isolated-test-only safety policy

The policy must forbid production and third-party targets, real credentials,
persistence, and data destruction. A result packet binds back to the exact
request digest and includes methods, sanitized evidence artifacts,
observations, counterevidence, residual gaps, and a safety attestation.

This repository does not execute the request and does not automatically convert
a returned `SUPPORTED_RUNTIME`, `REJECTED`, or `INCONCLUSIVE` outcome into an
adjudication decision.

Build a request with
`scripts/build-external-runtime-validation-request.mjs`; validate a request or
bound result with
`scripts/validate-external-runtime-validation-packet.mjs`.
