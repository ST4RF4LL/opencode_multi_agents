---
name: audit-coverage-accounting
description: Build and verify deterministic structural coverage for scope/files/functions/catalog plus semantic coverage for entry points, threats, Focus Areas, blind/seeded discovery tracks, and the system attack-chain pass. Use whenever an audit must prove both exact entity assignment and threat-led discovery coverage rather than relying on sampled or prose claims.
license: MIT
metadata:
  role: shared
  collection: common-subagent
---

# Audit Coverage Accounting

Use the bundled scripts as the source of truth for coverage. Do not replace their outputs with manually estimated counts.

Structural accounting, Coverage Plan/Ledger telemetry, and semantic completion are separate signals. The frozen `observe`/`release`/`assurance` policy decides which signals gate workflow acceptance; none may be rewritten to substitute for another.

## Build the scope

Run from the target repository root:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-scope-manifest.mjs \
  --root . \
  --audit-id <audit-id> \
  --output tmp/<audit-id>/recon/coverage/scope-manifest.json
```

In its default `--mode auto`, the scope builder uses the Git index plus untracked non-ignored files when a worktree is available. This avoids vendored dependencies, caches, and generated output already excluded by repository policy while recording ignored paths and audit/VCS infrastructure as exclusions. It falls back to a recursive filesystem walk outside Git. Use `--mode filesystem` only when ignored working-tree artifacts are intentionally part of the audit. Every included file is hashed, assigned an owner, and tagged with its required function parser.

Before inventorying functions, probe every parser actually required by the frozen scope:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-parser-capabilities.mjs \
  --root . --audit-id <audit-id> \
  --scope tmp/<audit-id>/recon/coverage/scope-manifest.json \
  --output tmp/<audit-id>/recon/coverage/parser-capabilities.json
```

This artifact records whether each configured frontend can create a real CPG from a smoke source; `joern-parse --list-languages` alone is not sufficient. An unavailable parser is a capability gap, not evidence that its source files contain no functions.

## Inventory functions once

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-function-manifests.mjs \
  --root . \
  --audit-id <audit-id> \
  --scope tmp/<audit-id>/recon/coverage/scope-manifest.json \
  --parser-capabilities tmp/<audit-id>/recon/coverage/parser-capabilities.json \
  --output-dir tmp/<audit-id>/recon/coverage \
  --jobs 2
```

The bounded driver creates the mandatory Java, JavaScript, and embedded-Web manifests and every additional parser language present in scope. Java uses the JDK compiler AST; Joern parses a temporary projection containing only files for the selected language and an isolated Joern workspace. Digest-bound valid outputs are reused automatically on resume; pass `--force true` only to deliberately rerun extraction. Any parse error or missing source file makes the relevant manifest incomplete.

The individual Java/Joern/embedded builders remain available for diagnosis. Do not call them again in threat modeling, planning, or gap rounds. Every `function_inventory_required` file must occur in exactly one complete function manifest.

If a capability artifact says a required parser is unavailable, strict inventory stops. An operator may explicitly produce a Recon-only partial index by passing `--allow-partial true` to both the function driver and routing-index builder, together with the same capability artifact. That index carries `complete=false` and structured function-inventory gaps. It may inform file-level threat modeling only; it must not be snapshotted, planned, ledger-initialized, or represented as a complete audit.

Build and verify the external-interface universe, then build the compact entity index used by threat modeling:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-interface-manifest.mjs \
  --root <workspace> --audit-id <audit-id> \
  --scope tmp/<audit-id>/recon/coverage/scope-manifest.json \
  --parser-capabilities tmp/<audit-id>/recon/coverage/parser-capabilities.json \
  --output tmp/<audit-id>/recon/coverage/interface-manifest.raw.json

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-source-anchored-interface-decisions.mjs \
  --audit-id <audit-id> \
  --input tmp/<audit-id>/recon/coverage/interface-manifest.raw.json \
  --output tmp/<audit-id>/recon/coverage/interface-decisions.json

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/resolve-interface-candidates.mjs \
  --audit-id <audit-id> \
  --input tmp/<audit-id>/recon/coverage/interface-manifest.raw.json \
  --decisions tmp/<audit-id>/recon/coverage/interface-decisions.json \
  --output tmp/<audit-id>/recon/coverage/interface-manifest.json

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/verify-interface-extractors.mjs \
  --audit-id <audit-id> \
  --scope tmp/<audit-id>/recon/coverage/scope-manifest.json \
  --interfaces tmp/<audit-id>/recon/coverage/interface-manifest.json \
  --output tmp/<audit-id>/recon/coverage/interface-extractor-coverage.json

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-threat-routing-index.mjs \
  --audit-id <audit-id> \
  --scope tmp/<audit-id>/recon/coverage/scope-manifest.json \
  --functions tmp/<audit-id>/recon/coverage/functions-java.json \
  --functions tmp/<audit-id>/recon/coverage/functions-javascript.json \
  --functions tmp/<audit-id>/recon/coverage/functions-embedded-web.json \
  --interfaces tmp/<audit-id>/recon/coverage/interface-manifest.json \
  --interface-extractors tmp/<audit-id>/recon/coverage/interface-extractor-coverage.json \
  --catalog .opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json \
  --output tmp/<audit-id>/recon/coverage/threat-routing-index.json
```

Repeat `--functions` for additional languages. The raw interface manifest distinguishes literal `CONFIRMED` declarations from executable/configuration `CANDIDATE` anchors. `build-source-anchored-interface-decisions.mjs` may confirm only gap-free candidates with exactly one frozen `interface-source-anchor`; it cannot infer dynamic routes, exposure, or authorization. Resolve all other candidates to `CONFIRMED` or `REJECTED` with a reason and non-empty evidence bound to the raw manifest digest; candidates never become required checks automatically. The extractor recognizes literal shell deployment port publishing in addition to source/config/spec anchors. Dynamic registrations, unsupported potential sources, symlinks, unresolved candidates, and extractor failures remain explicit inventory blockers. An empty confirmed-interface array is bounded only when every scoped file and candidate has a terminal decision. The routing index strips hashes, repeated lens metadata, and extractor internals while preserving file/function/interface/catalog IDs needed for threat routing.

## Record review coverage

Initialize each one-lens report from manifests before review:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/initialize-audit-report.mjs \
  --audit-id <audit-id> --round <round> --agent <agent> --session <session-id> \
  --lens <sink-driven|control-driven|config-driven> --language <language> \
  --scope tmp/<audit-id>/recon/coverage/scope-manifest.json \
  --functions <manifest> --catalog .opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json \
  --threat-model tmp/<audit-id>/recon/threat-model.json \
  --focus-areas tmp/<audit-id>/recon/focus-areas.json --focus-area <focus-area-id> \
  --output reports/vulnerability-mining/<agent>.<session-id>.audit-report.json
```

Repeat `--functions` for every manifest. The initializer validates the sealed threat/Focus artifacts, selects the exact primary assignment for the agent and Focus Area, sets `discovery_track=coverage`, and creates every required row as `GAP`. Auditors update only entity rows with evidence; do not rebuild or shorten arrays, hand-write coverage cells, or supply coverage counts.

For `ai-security-auditor`, also pass `--ai-surfaces tmp/<audit-id>/recon/ai-surfaces.json`. Each initializer call selects one `domain=ai` Focus Area assignment; their union must equal every reviewable file, every inventoried function, and every AI catalog item.

For a later gap round, either repeat `--file-id`, `--function-id`, and `--catalog-id`, or pass `--assignment <json>`. The subset must remain inside the original Focus Area assignment. Without a follow-up assignment, the initializer uses the Focus Area's complete primary assignment. The structural verifier retains earlier-round records for entity/lens keys not present in a later subset report.

Name every single-lens report `*.audit-report.json` and include `round`, one canonical `audit_strategy`, all D1-D10 dimensions, the frozen scope digest, and:

- `focus_area_id` and `discovery_track=coverage`.

- `file_coverage`: one entry for every assigned file ID. Base owner sessions use `domain=base`; the AI overlay uses `domain=ai`.
- `function_coverage`: one entry for every assigned function ID with the same explicit base/AI domain rule.
- `catalog_coverage`: one entry for every required unified application/platform/AI catalog ID.

Catalog records include `domain=java`, `domain=web`, `domain=platform`, `domain=c-cpp`, `domain=python`, or `domain=ai`. When a catalog entry applies to multiple active domains, each domain owner reviews it independently.

Use only `REVIEWED`, `FINDING`, or `GAP` for entity rows. Do not submit `N/A` for file/function/catalog rows. A reported finding never closes a remaining gap.

After editing entity rows, derive the D1-D10 cells in place:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/reconcile-audit-report.mjs \
  --report reports/vulnerability-mining/<agent>.<session>.audit-report.json \
  --scope tmp/<audit-id>/recon/coverage/scope-manifest.json \
  --catalog .opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json
```

The reconciler computes the complete target universe from the report's frozen assignment and catalog dimensions. It sets `PASS`, `FINDING`, or `GAP`; it emits `N/A` only when that dimension has zero machine-assigned targets. Never add `targets_discovered` or `targets_reviewed`: the verifier rejects self-reported totals.

## Build and execute Coverage Plan v3

After the sealed Focus Areas partition every file/function/catalog primary assignment, snapshot all inputs, validate catalog v2, and build the immutable sparse plan:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/snapshot-coverage-inputs.mjs \
  --audit-id <audit-id> \
  --scope tmp/<audit-id>/recon/coverage/scope-manifest.json \
  --functions tmp/<audit-id>/recon/coverage/functions-java.json \
  --functions tmp/<audit-id>/recon/coverage/functions-javascript.json \
  --functions tmp/<audit-id>/recon/coverage/functions-embedded-web.json \
  --interfaces tmp/<audit-id>/recon/coverage/interface-manifest.json \
  --interface-extractors tmp/<audit-id>/recon/coverage/interface-extractor-coverage.json \
  --catalog .opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json \
  --threat-model tmp/<audit-id>/recon/threat-model.json \
  --focus-areas tmp/<audit-id>/recon/focus-areas.json \
  --output-dir reports/coverage/<audit-id>/inputs

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/validate-vulnerability-catalog-v2.mjs \
  --catalog reports/coverage/<audit-id>/inputs/application-ai-vulnerability-catalog.json

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-coverage-plan.mjs \
  --audit-id <audit-id> \
  --coverage-mode observe \
  --scope reports/coverage/<audit-id>/inputs/scope-manifest.json \
  --functions reports/coverage/<audit-id>/inputs/functions-java.json \
  --functions reports/coverage/<audit-id>/inputs/functions-javascript.json \
  --functions reports/coverage/<audit-id>/inputs/functions-embedded-web.json \
  --interfaces reports/coverage/<audit-id>/inputs/interface-manifest.json \
  --interface-extractors reports/coverage/<audit-id>/inputs/interface-extractor-coverage.json \
  --catalog reports/coverage/<audit-id>/inputs/application-ai-vulnerability-catalog.json \
  --focus-areas reports/coverage/<audit-id>/inputs/focus-areas.json \
  --snapshot-index reports/coverage/<audit-id>/inputs/snapshot-index.json \
  --output reports/coverage/coverage-plan.<audit-id>.json
```

Repeat `--functions` for every frozen language manifest. The Plan builder accepts only exact paths and byte hashes from the snapshot index; live or stale inputs are rejected. Schema v2 plans and ledgers must be rebuilt from a new snapshot and are not upgraded in place. The v3 plan contains:

- one mandatory negative-discovery baseline for every active `domain × vulnerability type × lens`;
- interface checks only for explicitly `CONFIRMED` interfaces selected by the catalog's versioned applicability profile;
- planner-owned `NOT_APPLICABLE` decisions for non-intersecting pairs;
- normalized `source_sets`, referenced by ID instead of repeating source arrays on every check;
- separate inventory counts and blocker IDs for candidates, unresolved interfaces, and extractor gap files;
- a unique `focus_area_id` on every atomic check.
- one content-addressed `coverage_unit` for each Focus Area assignment/domain; lenses and atomic checks are internal dimensions of that unit.

`--coverage-mode` accepts `observe` (default), `release`, or `assurance`. `observe` records honest telemetry without making unfinished checks a workflow blocker. `release` requires all policy-tagged AI, external-interface, and identity/privilege units. `assurance` preserves the strict all-required-checks gate. The selected mode is frozen in the Plan; changing it requires a new Plan and Ledger.

Python and C/C++ use the same shared catalog selector as the structural verifier; AI uses `AI-*`; Java, Web, and Platform use their direct catalog selectors. Every atomic subject/type/domain group must contain all three lenses. A plan is complete only when `U=0` and its interface inventory is bounded; candidates and extractor gaps do not inflate `R`, but they still block complete finalization.

Initialize the ledger once:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/initialize-coverage-ledger.mjs \
  --plan reports/coverage/coverage-plan.<audit-id>.json \
  --ledger reports/coverage/<audit-id>/ledger/coverage-ledger.jsonl
```

For a local, explicitly incomplete handoff, use the same service-owned checkpoint semantics rather than editing the ledger:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/checkpoint-coverage-ledger.mjs \
  --plan reports/coverage/coverage-plan.<audit-id>.json \
  --ledger reports/coverage/<audit-id>/ledger/coverage-ledger.jsonl \
  --idempotency-key <stable-key> --label <reason>
```

It produces `PARTIAL_CHECKPOINT`, never `FINALIZED_COMPLETE`, and preserves every unresolved check as a gap.

When an explicitly authorized budget, round, or operator stop ends the audit,
seal a terminal partial ledger instead of relabeling a checkpoint. This prevents
any later Ledger mutation and permits only a prominently partial final report:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/finalize-partial-coverage-ledger.mjs \
  --plan reports/coverage/coverage-plan.<audit-id>.json \
  --ledger reports/coverage/<audit-id>/ledger/coverage-ledger.jsonl \
  --idempotency-key <stable-key> \
  --termination-reason round-limit-reached
```

Allowed termination reasons are `budget-exhausted`, `round-limit-reached`, and
`operator-stop`. `FINALIZED_PARTIAL` never authorizes complete coverage; it is
immutable, unlike `PARTIAL_CHECKPOINT`.

Coverage sessions never edit the plan or canonical ledger. The `coverage_ledger` MCP is intentionally paginated: do not request or paste a full plan, ledger, member list, or all gaps into model context. Use the tools in this order:

1. `coverage_get_unit` filtered by exact `audit_id`, `focus_area_id`, domain, or assignment. It returns compact assignment-unit counts and state without atomic member IDs.
2. `coverage_begin_unit` once per executing session. It returns a session-bound, unit-scoped `assignment_token`.
3. Treat lenses as internal unit dimensions. A lens-specific session calls `coverage_submit_attestation(state: "PARTIAL")` once for its completed lens; a combined session may use `state=COMPLETE` only when all required lenses are covered and the gap list is empty. Include `source_scope: "required"`, tool/version, a bounded result payload or artifact, and only exceptional `gap_check_ids`. The service merges lens attestations and expands each all-minus-gaps proof into exact check state without returning the frozen member universe.
4. Use `coverage_get_unit_checks`, `coverage_get_subject_sources`, or `coverage_get_subject_interfaces` only for targeted gap classification, finding binding, or diagnostics. Do not enumerate them in a no-finding path.
5. Coverage execution and finding adjudication are independent. A unit attestation does not assert `NO_FINDING`; before or after it, bind a finding or exact result through the check-scoped fallback: `coverage_get_packet`/`coverage_get_unit_checks` → `coverage_inspect_subject` → `coverage_record_tool_result` → `coverage_submit_decision`. A `FINDING` includes one unique standalone Finding v2 JSON artifact per ID and closes only its bound atomic check. `coverage_delegate_assignment` remains available only for this fallback.
6. `coverage_get_gaps` routes exceptional follow-up work. It remains check-exact and cursor-paginated.
7. `coverage_checkpoint` creates a nonterminal diagnostic checkpoint. `coverage_finalize` seals according to the frozen policy: `FINALIZED_OBSERVED`, `FINALIZED_RELEASE`, or strict `FINALIZED_COMPLETE`.

Execution states are `PLANNED → INSPECTED → VERIFIED`, or terminally incomplete `GAP`/`INVALIDATED`. Result states are independently `NO_FINDING`, `FINDING`, or `INCONCLUSIVE`. `VERIFIED` requires a valid receipt from the active assignment. `FINDING` closes only its atomic check; it never closes other types, interfaces, or lenses. Agents cannot submit `N/A`. Direct writes to `reports/coverage/<audit-id>/ledger/` are denied. The service serializes mutations across processes, fsyncs each event, and authenticates the public hash chain with a mode-0600 HMAC key sidecar.

Record shape:

```json
{
  "function_id": "function:<stable-id>",
  "domain": "base",
  "status": "REVIEWED",
  "dimensions_reviewed": ["D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"],
  "evidence": [{"kind": "function-location", "function_id": "function:<stable-id>", "path": "src/...", "code_sha256": "<frozen hash>", "qualified_name": "Example.method", "line_start": 42}],
  "finding_ids": []
}
```

File evidence uses `kind=source-location` and must bind `file_id`, exact frozen `path`, `sha256`, and `line_start`. A scoped symlink instead uses `kind=symlink-location` with its `file_id`, path, and frozen `link_target`. Catalog evidence uses `kind=catalog-review` and must bind `catalog_id`, domain, lens, catalog profile, and the SHA-256 of its exact lens question. `FINDING` requires IDs present in the report's `findings`; each finding must declare only the dimensions it actually supports. A closed `REVIEWED`/`FINDING` row must have `gap_reason: null`; `GAP` always prevents completion and must carry a reason. The initializer's `assignment-anchor` is valid only while a row remains `GAP`.

## Verify before reporting

Seal `threat-model.json` and `focus-areas.json` with `seal-semantic-manifest.mjs` before creating the snapshot used by the Plan. Snapshotting preflights the exact primary file/function/catalog partition and rejects missing or duplicate function-manifest membership, so Focus Area omissions fail before Plan construction. It may preserve interface candidates or extractor gaps for a partial, auditable run; those blockers remain unbounded inventory and cannot be finalized as complete.

When restarting an audit whose non-cache frozen source hashes are exactly equal to a prior audit, `reseed-semantic-manifests.mjs` may carry forward only the prior threat hypotheses and Focus partition. It marks both artifacts `revalidation_required=true`, removes known local `.atlas/` cache assignments, and never carries forward coverage, Ledger decisions, Finding states, adjudication, chains, or final-report conclusions. Use it only before the new snapshot and re-run the required semantic review:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/reseed-semantic-manifests.mjs \
  --audit-id <new-audit-id> --scope tmp/<new-audit-id>/recon/coverage/scope-manifest.json \
  --source-scope reports/coverage/<prior-audit-id>/inputs/scope-manifest.json \
  --source-threat-model reports/coverage/<prior-audit-id>/inputs/threat-model.json \
  --source-focus-areas reports/coverage/<prior-audit-id>/inputs/focus-areas.json \
  --threat-output tmp/<new-audit-id>/recon/threat-model.json \
  --focus-output tmp/<new-audit-id>/recon/focus-areas.json
```

After `coverage_finalize`, run the v3 gate. Use `--mode policy` for `observe`/`release`, or `--mode complete` for an assurance/full-coverage claim. Policy mode may exit zero while `coverage_status` remains `PARTIAL` or `BLOCKED`; it reports `policy_satisfied=true` and never relabels that state as complete coverage. The gate invokes the structural verifier itself from frozen arguments, persists that trusted artifact, derives the JSON summary and Markdown from the same state, and emits the authoritative verification. It rejects a caller-supplied `--structural` artifact:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/verify-coverage-v3.mjs \
  --mode policy \
  --root . \
  --audit-id <audit-id> \
  --scope reports/coverage/<audit-id>/inputs/scope-manifest.json \
  --functions reports/coverage/<audit-id>/inputs/functions-java.json \
  --functions reports/coverage/<audit-id>/inputs/functions-javascript.json \
  --functions reports/coverage/<audit-id>/inputs/functions-embedded-web.json \
  --interfaces reports/coverage/<audit-id>/inputs/interface-manifest.json \
  --interface-extractors reports/coverage/<audit-id>/inputs/interface-extractor-coverage.json \
  --snapshot-index reports/coverage/<audit-id>/inputs/snapshot-index.json \
  --reports-dir reports/vulnerability-mining \
  --catalog reports/coverage/<audit-id>/inputs/application-ai-vulnerability-catalog.json \
  --plan reports/coverage/coverage-plan.<audit-id>.json \
  --ledger reports/coverage/<audit-id>/ledger/coverage-ledger.jsonl \
  --structural-output reports/coverage/coverage-structural-v1.<audit-id>.json \
  --summary-output reports/coverage/coverage-summary.<audit-id>.json \
  --markdown-output reports/coverage/coverage-summary.<audit-id>.md \
  --output reports/coverage/coverage-verification.<audit-id>.json

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/verify-coverage-summary.mjs \
  --mode policy \
  --summary reports/coverage/coverage-summary.<audit-id>.json \
  --markdown reports/coverage/coverage-summary.<audit-id>.md \
  --plan reports/coverage/coverage-plan.<audit-id>.json \
  --ledger reports/coverage/<audit-id>/ledger/coverage-ledger.jsonl \
  --structural reports/coverage/coverage-structural-v1.<audit-id>.json
```

Repeat `--functions` for every snapshotted language. A policy-accepted non-complete report uses `build-final-report-model.mjs --mode policy-final`; its visible disclaimer preserves all remaining gaps. For an interrupted, non-final run, call `coverage_checkpoint`, then pass `--mode partial` to both v3 verification commands. Partial mode writes sealed diagnostic artifacts, exits nonzero, and never produces `complete=true`.

`verify-coverage-v2.mjs` remains only as a caller-compatible wrapper around the v3 core. It does not accept or migrate v2 plans or ledgers.

Also run `verify-semantic-coverage.mjs` with the snapshot index, vulnerability-mining reports directory, validated Finding Adjudication manifest, and final Attack-chain v2 report. A complete audit requires authoritative Coverage v3, verified JSON/Markdown summary, and semantic artifacts to say `complete: true`.

Structural completion requires:

1. No scope drift: current file hashes equal the scope manifest.
2. No unreadable or unassigned files.
3. No parser errors or missing function-bearing files.
4. Every required file and function has both base-owner and independent AI-overlay records for all three lenses.
5. Every required catalog item has all three lens records for each applicable active domain, including AI.
6. The external-interface manifest and extractor verification are digest-bound to the scope, and no indeterminate/failed extractor remains.
7. No `GAP`, invalid `N/A`, unknown IDs, or conflicting ownership remains.
8. Every D1-D10 cell exactly matches `reconcile-audit-report.mjs`; every closed row has source/function/catalog evidence bound to frozen IDs and hashes.
9. Every required catalog-domain negative-discovery and applicable interface/type check has all three lenses and a receipt-backed `VERIFIED` ledger decision.
10. The ledger sequence, public hash chain, service HMAC chain, plan/snapshot binding, `FINALIZE_COMPLETE` event, and exact JSON/Markdown summary are valid.

Semantic completion requires:

1. Every entry point has threats or evidence-backed deprioritization and no blocking open question remains.
2. Every threat maps to a Focus Area and has at least one complete owning Focus Area under every lens.
3. Every Focus Area primary assignment has one complete coverage report under all three lenses.
4. Every Focus Area has a valid blind artifact and every history-seeded area has a valid seeded-variant artifact.
5. The system attack-chain report accounts for every Focus Area, trust boundary, and asset.

Coverage metrics use `R=required`, `V=verified`, `U=unknown`, and `N=not applicable` for materialized atomic checks only. Known coverage is `V/R`; when inventory is bounded, the conservative lower bound is `V/(R+U)`. Candidates, unresolved interfaces, and extractor gap files are a separate inventory universe. If that universe is unbounded, the total and interface lower-bound percentages are `null` with state `UNBOUNDED`, never an optimistic numeric value; the vulnerability-type baseline retains its own correctly scoped ratio. `R=0` renders `NOT_APPLICABLE`, never 100%. Interfaces split ingress, egress, and bidirectional. Files are complete only when every required file record and contained function check is complete.

Each verifier exits nonzero on any violation. Only all three terminal gates authorize a complete structural/type/interface-and-semantic coverage statement.

The structural artifact emits a digest-bound `finding_intake` manifest. Only `accepted_findings` may participate in Ledger reconciliation; `quarantined_findings` are diagnostic only. The v3 gate rejects any coverage-track finding with no exact Ledger `FINDING` artifact, a mismatched primary check, or a mismatched canonical Finding v2 digest.

## Render the final report deterministically

Do not hand-write the sealed final Markdown. After the coverage summary, Finding
Adjudication input/output, the script-derived CVSS 3.1 assessment, and
Attack-chain v2 artifact all validate, build a digest-bound model, render it,
and byte-verify the result. Only supported findings receive a CVSS assessment;
the claim file supplies a vector, rationale, assumptions, and evidence refs,
while the script derives the number and rating:

```sh
node .opencode/skills/common-subagent/finding-adjudication/scripts/build-cvss-assessment.mjs \
  --claims reports/adjudication/cvss-claims.<audit-id>.r<round>.json \
  --adjudication reports/adjudication/security-finding-adjudicator.<audit-id>.r<round>.json \
  --output reports/adjudication/cvss-assessment.<audit-id>.r<round>.json
```

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-final-report-model.mjs \
  --audit-id <audit-id> \
  --mode final \
  --coverage-summary reports/coverage/coverage-summary.<audit-id>.json \
  --adjudication-input reports/adjudication/finding-input.<audit-id>.r<round>.json \
  --adjudication reports/adjudication/security-finding-adjudicator.<audit-id>.r<round>.json \
  --cvss reports/adjudication/cvss-assessment.<audit-id>.r<round>.json \
  --chains reports/attack-chains/security-attack-chain-hunter.<audit-id>.r<round>.json \
  --output reports/final/security-audit-report-model.<audit-id>.json

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/render-final-report.mjs \
  --model reports/final/security-audit-report-model.<audit-id>.json \
  --output reports/final/security-audit-report.<audit-id>.md

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/verify-final-report.mjs \
  --model reports/final/security-audit-report-model.<audit-id>.json \
  --markdown reports/final/security-audit-report.<audit-id>.md
```

The model retains all non-admitted finding decisions and contradicted chains as
residual outcomes. Only `SUPPORTED_STATIC`/`SUPPORTED_RUNTIME` findings and
adjudication-bound `CONDITIONAL`/supported chains appear as final results.
`verify-final-report.mjs` rejects any byte drift, `CONFIRMED` label, or direct
reference to an unadjudicated raw attack-chain artifact.

For an incomplete run, never use `--mode final` or write under `reports/final/`.
After `coverage_checkpoint` and partial coverage verification, a zero-candidate
input may use `build-empty-finding-adjudication.mjs`,
`build-empty-cvss-assessment.mjs`, and `build-empty-attack-chain-report.mjs`; then pass `--mode
checkpoint` and render under `reports/checkpoints/`. The checkpoint renderer
labels it nonterminal and therefore ineligible for third-party final-report
review.

Only after a `FINALIZED_PARTIAL` seal may a terminal partial primary be rendered
with `--mode partial-final`; it must explicitly retain gaps and may never be
labeled complete. A checkpoint is not interchangeable with this terminal form.

## Claim boundary

The structural gate proves base-owner plus AI-overlay accounting over frozen files, source-defined functions, executable template units recognized by configured AST/CPG extractors, catalog domains, and deterministic source/spec/config external-interface anchors. Coverage v3 additionally proves execution of every snapshot-bound required vulnerability-type/interface/lens check with assignment-authorized, service-attested receipts and a finalized authenticated ledger. These are coverage-completion claims, not proof that no vulnerability exists. The semantic gate proves terminal entry-point threat decisions, Focus Area/lens/track execution, and a system pass over declared boundaries/assets. Unsupported potential source, generated code absent from the repository, hosted model/tool behavior, and runtime-only controls remain gaps.
