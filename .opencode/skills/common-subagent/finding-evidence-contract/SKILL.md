---
name: finding-evidence-contract
description: Validate and bind security finding artifacts before they enter coverage accounting, correlation, or a final audit report. Use when a source-audit agent emits a candidate finding, when the Coverage Ledger records a FINDING decision, or when a verifier must reject incomplete, misclassified, or unproven finding evidence.
---

# Finding Evidence Contract

Create a standalone JSON object conforming to `schemas/finding-v2.schema.json` for each candidate. Keep the mined conclusion at `CANDIDATE`; only an independent adjudication artifact may promote it.

Run `scripts/validate-finding-artifact.mjs` before submitting a coverage-track FINDING to the Ledger. Bind the candidate to its audit, frozen scope, primary check, Focus Area, domain, lens, vulnerability type, and explicitly claimed dimensions.

Every candidate must contain a concrete primary location, typed evidence facts, reachability and attacker-influence assessments, examined guards, uncertainty, severity rationale, remediation, and source-report provenance. Do not use a free-text finding ID occurrence as evidence.

Candidate severity is qualitative. It may include only a `PROVISIONAL` CVSS 3.1
vector with no number or rating; `score`, `base_score`, `rating`, and final
CVSS fields are rejected. Only the post-adjudication CVSS assessment builder
derives a final score and severity.

For coverage-track findings, `classification.discovery_track` is `coverage`, `routing.primary_check_id` identifies the exact ledger check, and `classification.dimension_claims` must be a subset of that check's dimensions. Blind and seeded findings remain candidates and never close coverage checks.

Use `scripts/finding-contract.mjs` as the shared implementation. Verifiers and Ledger code must call the same functions rather than duplicating field checks.
