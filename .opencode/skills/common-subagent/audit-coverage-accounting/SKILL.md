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

Structural accounting, Coverage Plan scheduling, and semantic completion are separate signals. The frozen `observe`/`release`/`assurance` policy guides audit depth; none may be rewritten to substitute for another.

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

If a capability artifact says a required parser is unavailable, strict inventory stops. An operator may explicitly produce a Recon-only partial index by passing `--allow-partial true` to both the function driver and routing-index builder, together with the same capability artifact. That index carries `complete=false` and structured function-inventory gaps. It may inform file-level threat modeling only; it must not be snapshotted, scheduled, or represented as a complete audit.

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

After the sealed Focus Areas partition every file/function/catalog primary
assignment, build the scheduler input directly from the frozen Recon directory:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-coverage-plan.mjs \
  --audit-id <audit-id> \
  --recon-dir tmp/<audit-id>/recon \
  --catalog .opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json \
  --coverage-mode observe \
  --output reports/coverage/coverage-plan.<audit-id>.json
```

`--recon-dir` discovers every `functions-<language>.json` manifest itself. Do
not call `snapshot-coverage-inputs.mjs` for new audits: it duplicates large
inputs, expands command lines, and has no value for the local scheduler. The
Plan builder validates the existing sealed manifests in place and emits only a
compact command summary. Plans are rebuilt when Recon/Focus Areas change. The
plan contains:

- one mandatory negative-discovery baseline for every active `domain × vulnerability type × lens`;
- interface checks only for explicitly `CONFIRMED` interfaces selected by the catalog's versioned applicability profile;
- planner-owned `NOT_APPLICABLE` decisions for non-intersecting pairs;
- normalized `source_sets`, referenced by ID instead of repeating source arrays on every check;
- separate inventory counts and blocker IDs for candidates, unresolved interfaces, and extractor gap files;
- a unique `focus_area_id` on every atomic check.
- one content-addressed `coverage_unit` for each Focus Area assignment/domain; lenses and atomic checks are internal dimensions of that unit.

`--coverage-mode` accepts `observe` (default), `release`, or `assurance`. The selected mode is frozen in the Plan; changing it requires a new Plan. It guides reporting depth, but never creates a per-check event log or substitutes for the orchestrator-owned task state.

Python and C/C++ use the same shared catalog selector as the structural verifier; AI uses `AI-*`; Java, Web, and Platform use their direct catalog selectors. Every atomic subject/type/domain group must contain all three lenses. A plan is complete only when `U=0` and its interface inventory is bounded; candidates and extractor gaps do not inflate `R`, but they still block complete finalization.

Initialize the local queue once after the Plan is frozen. The queue is not an MCP, has no hash chain, and is owned only by the orchestrator:

```sh
node "$AUDIT_TODO_CLI" init \
  --todo "$AUDIT_TODO_PATH" \
  --audit-id <audit-id> \
  --plan reports/coverage/coverage-plan.<audit-id>.json
```

The local queue creates one item for each `Focus Area × domain` coverage unit.
All three lenses and the unit's atomic checks stay inside that item; they must
not become OpenCode todo entries or individual subagent tasks. The orchestrator
claims at most four bounded work packets at a time, with at most twelve items
per packet:

```sh
node "$AUDIT_TODO_CLI" claim --todo "$AUDIT_TODO_PATH" --packets 4 --items 12
```

Each specialist receives only one returned packet. It writes its normal
vulnerability-mining report and one JSON handoff under
`reports/audit-todo/<audit-id>/<packet-id>.json`. The handoff lists each packet
item exactly once as `DONE` (existing relative `report_path`, optional finding
IDs) or `GAP` (concise reason). The orchestrator checks only its shape and the
referenced report file, then records it with `audit-todo complete`. It must not
review source code or decide whether a finding is true while doing that.

If a packet fails before a valid handoff, the orchestrator calls
`audit-todo fail`; recoverable failures return to `PENDING`, while an exhausted
or operator-blocked item is `FAILED` and remains visible. On restart call
`audit-todo recover`, then claim only PENDING items. `DONE` and `GAP` are
terminal for scheduling, but `GAP` must remain in the correlation and final
report. The final completion gate is: no PENDING/RUNNING/FAILED item, accepted
handoffs for every claimed packet, and an existing final Chinese Markdown
report.

Specialists never read, mutate, or infer queue state. They own source analysis
and findings; the orchestrator owns dispatch and recording only. Result states
inside reports remain independently `NO_FINDING`, `FINDING`, or
`INCONCLUSIVE`; a `DONE` task never closes a different type, interface, or
lens.

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

Seal `threat-model.json` and `focus-areas.json` with `seal-semantic-manifest.mjs` before building the Plan. The direct Recon planner preflights the exact primary file/function/catalog partition and rejects missing or duplicate function-manifest membership, so Focus Area omissions fail before Plan construction. It may preserve interface candidates or extractor gaps for a partial, auditable run; those blockers remain unbounded inventory and cannot be finalized as complete.

When restarting an audit whose non-cache frozen source hashes are exactly equal to a prior audit, `reseed-semantic-manifests.mjs` may carry forward only the prior threat hypotheses and Focus partition. It marks both artifacts `revalidation_required=true`, removes known local `.atlas/` cache assignments, and never carries forward coverage reports, local task state, Finding states, adjudication, chains, or final-report conclusions. Use it only before the new snapshot and re-run the required semantic review:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/reseed-semantic-manifests.mjs \
  --audit-id <new-audit-id> --scope tmp/<new-audit-id>/recon/coverage/scope-manifest.json \
  --source-scope reports/coverage/<prior-audit-id>/inputs/scope-manifest.json \
  --source-threat-model reports/coverage/<prior-audit-id>/inputs/threat-model.json \
  --source-focus-areas reports/coverage/<prior-audit-id>/inputs/focus-areas.json \
  --threat-output tmp/<new-audit-id>/recon/threat-model.json \
  --focus-output tmp/<new-audit-id>/recon/focus-areas.json
```

After all packets have handed off, use `audit-todo stats` to confirm task
terminality. The structural verifier and, after adjudication/final chains, the
semantic verifier both read the same Recon directory directly; neither accepts
or creates a snapshot index:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/verify-coverage.mjs \
  --root "$AUDIT_SOURCE_ROOT" \
  --audit-id <audit-id> \
  --recon-dir tmp/<audit-id>/recon \
  --reports-dir reports/vulnerability-mining \
  --catalog .opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json \
  --output reports/coverage/coverage-structural-v1.<audit-id>.json

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/verify-semantic-coverage.mjs \
  --audit-id <audit-id> \
  --recon-dir tmp/<audit-id>/recon \
  --catalog .opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json \
  --reports-dir reports/vulnerability-mining \
  --adjudication reports/adjudication/security-finding-adjudicator.<audit-id>.r<round>.json \
  --attack-chain-report reports/attack-chains/security-attack-chain-hunter.<audit-id>.r<round>.json \
  --output reports/coverage/semantic-coverage.<audit-id>.json
```

Then build the final-report input summary from the plan and local queue:

```sh
node .opencode/scripts/build-local-audit-summary.mjs \
  --audit-id <audit-id> \
  --plan reports/coverage/coverage-plan.<audit-id>.json \
  --todo "$AUDIT_TODO_PATH" \
  --output reports/coverage/coverage-summary.<audit-id>.json
```

A complete audit requires valid structural and semantic artifacts, terminal local task state, and a final report; no event ledger or per-check HMAC finalization is involved.

Structural completion requires:

1. No scope drift: current file hashes equal the scope manifest.
2. No unreadable or unassigned files.
3. No parser errors or missing function-bearing files.
4. Every required file and function has both base-owner and independent AI-overlay records for all three lenses.
5. Every required catalog item has all three lens records for each applicable active domain, including AI.
6. The external-interface manifest and extractor verification are digest-bound to the scope, and no indeterminate/failed extractor remains.
7. No `GAP`, invalid `N/A`, unknown IDs, or conflicting ownership remains.
8. Every D1-D10 cell exactly matches `reconcile-audit-report.mjs`; every closed row has source/function/catalog evidence bound to frozen IDs and hashes.
9. Every required catalog-domain negative-discovery and applicable interface/type check has all three lenses inside its completed packet report or remains a visible GAP.
10. The local task list is bound to the plan, each claimed packet has one structurally valid handoff, and each DONE item points to an existing report.

Semantic completion requires:

1. Every entry point has threats or evidence-backed deprioritization and no blocking open question remains.
2. Every threat maps to a Focus Area and has at least one complete owning Focus Area under every lens.
3. Every Focus Area primary assignment has one complete coverage report under all three lenses.
4. Every Focus Area has a valid blind artifact and every history-seeded area has a valid seeded-variant artifact.
5. The system attack-chain report accounts for every Focus Area, trust boundary, and asset.

Coverage metrics use `R=required`, `V=verified`, `U=unknown`, and `N=not applicable` for materialized atomic checks only. Known coverage is `V/R`; when inventory is bounded, the conservative lower bound is `V/(R+U)`. Candidates, unresolved interfaces, and extractor gap files are a separate inventory universe. If that universe is unbounded, the total and interface lower-bound percentages are `null` with state `UNBOUNDED`, never an optimistic numeric value; the vulnerability-type baseline retains its own correctly scoped ratio. `R=0` renders `NOT_APPLICABLE`, never 100%. Interfaces split ingress, egress, and bidirectional. Files are complete only when every required file record and contained function check is complete.

Each verifier exits nonzero on any violation. Structural and semantic gates plus terminal local task state authorize a complete structural/type/interface-and-semantic coverage statement.

The structural artifact emits a digest-bound `finding_intake` manifest. Only `accepted_findings` from packet-backed reports may enter adjudication; `quarantined_findings` are diagnostic only. Reconciliation rejects a coverage-track finding with no accepted packet report, a mismatched source binding, or a mismatched canonical Finding v2 digest.

## Render the final report deterministically

Do not hand-write the sealed final Markdown. After the local-task-derived coverage summary, Finding
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
  --mode <final-if-no-gap|policy-final-if-any-gap> \
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

If there is any local `GAP`, use `--mode policy-final`; the generated Markdown
must preserve all gaps. Use `--mode final` only when every local item is DONE.
For an interrupted run, do not write under `reports/final/`; leave the queue
recoverable and retain the intermediate reports for the next orchestrator run.

## Claim boundary

The structural gate proves base-owner plus AI-overlay accounting over frozen files, source-defined functions, executable template units recognized by configured AST/CPG extractors, catalog domains, and deterministic source/spec/config external-interface anchors. The local task list additionally proves that every scheduled `Focus Area × domain` packet has a completed report or an explicit GAP; it does not claim that every atomic check was independently verified. These are coverage-completion claims, not proof that no vulnerability exists. The semantic gate proves terminal entry-point threat decisions, Focus Area/lens/track execution, and a system pass over declared boundaries/assets. Unsupported potential source, generated code absent from the repository, hosted model/tool behavior, and runtime-only controls remain gaps.
