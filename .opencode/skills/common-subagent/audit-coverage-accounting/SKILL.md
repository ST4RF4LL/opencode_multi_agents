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

Structural, Coverage Plan/Ledger v2, and semantic completion are separate gates. None can substitute for another.

## Build the scope

Run from the target repository root:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-scope-manifest.mjs \
  --root . \
  --audit-id <audit-id> \
  --output tmp/<audit-id>/recon/coverage/scope-manifest.json
```

In its default `--mode auto`, the scope builder uses the Git index plus untracked non-ignored files when a worktree is available. This avoids vendored dependencies, caches, and generated output already excluded by repository policy while recording ignored paths and audit/VCS infrastructure as exclusions. It falls back to a recursive filesystem walk outside Git. Use `--mode filesystem` only when ignored working-tree artifacts are intentionally part of the audit. Every included file is hashed, assigned an owner, and tagged with its required function parser.

## Inventory functions once

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-function-manifests.mjs \
  --root . \
  --audit-id <audit-id> \
  --scope tmp/<audit-id>/recon/coverage/scope-manifest.json \
  --output-dir tmp/<audit-id>/recon/coverage \
  --jobs 2
```

The bounded driver creates the mandatory Java, JavaScript, and embedded-Web manifests and every additional parser language present in scope. Java uses the JDK compiler AST; Joern parses a temporary projection containing only files for the selected language instead of rebuilding a CPG from the whole repository for every manifest. Digest-bound valid outputs are reused automatically on resume; pass `--force true` only to deliberately rerun extraction. Any parse error or missing source file makes the relevant manifest incomplete.

The individual Java/Joern/embedded builders remain available for diagnosis. Do not call them again in threat modeling, planning, or gap rounds. Every `function_inventory_required` file must occur in exactly one complete function manifest.

Build and verify the external-interface universe, then build the compact entity index used by threat modeling:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-interface-manifest.mjs \
  --root <workspace> --audit-id <audit-id> \
  --scope tmp/<audit-id>/recon/coverage/scope-manifest.json \
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

Repeat `--functions` for additional languages. The interface manifest distinguishes literal `CONFIRMED` declarations from executable/configuration `CANDIDATE` anchors. Dynamic registrations, unsupported potential sources, symlinks, and extractor failures produce blocking gaps; an empty interface array is complete only when every scoped file has a terminal extractor decision. The routing index strips hashes, repeated lens metadata, and extractor internals while preserving file/function/interface/catalog IDs needed for threat routing.

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

Catalog records include `domain=java`, `domain=web`, `domain=platform`, or `domain=ai`. When a catalog entry applies to multiple active domains, each domain owner reviews it independently.

Use only `REVIEWED`, `FINDING`, or `GAP` for entity rows. Do not submit `N/A` for file/function/catalog rows. A reported finding never closes a remaining gap.

After editing entity rows, derive the D1-D10 cells in place:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/reconcile-audit-report.mjs \
  --report reports/vulnerability-mining/<agent>.<session>.audit-report.json \
  --scope tmp/<audit-id>/recon/coverage/scope-manifest.json \
  --catalog .opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json
```

The reconciler computes the complete target universe from the report's frozen assignment and catalog dimensions. It sets `PASS`, `FINDING`, or `GAP`; it emits `N/A` only when that dimension has zero machine-assigned targets. Never add `targets_discovered` or `targets_reviewed`: the verifier rejects self-reported totals.

## Build and execute Coverage Plan v2

After the sealed Focus Areas partition every file/function/catalog primary assignment, validate catalog v2 and build the immutable sparse plan:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/validate-vulnerability-catalog-v2.mjs \
  --catalog reports/coverage/<audit-id>/inputs/application-ai-vulnerability-catalog.json

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-coverage-plan.mjs \
  --audit-id <audit-id> \
  --scope reports/coverage/<audit-id>/inputs/scope-manifest.json \
  --functions reports/coverage/<audit-id>/inputs/functions-java.json \
  --functions reports/coverage/<audit-id>/inputs/functions-javascript.json \
  --functions reports/coverage/<audit-id>/inputs/functions-embedded-web.json \
  --interfaces reports/coverage/<audit-id>/inputs/interface-manifest.json \
  --interface-extractors reports/coverage/<audit-id>/inputs/interface-extractor-coverage.json \
  --catalog reports/coverage/<audit-id>/inputs/application-ai-vulnerability-catalog.json \
  --focus-areas reports/coverage/<audit-id>/inputs/focus-areas.json \
  --output reports/coverage/coverage-plan.<audit-id>.json
```

Repeat `--functions` for every frozen language manifest. The plan contains:

- one mandatory negative-discovery baseline for every active `domain × vulnerability type × lens`;
- interface checks only for applicable domains whose vulnerability dimensions intersect the interface dimensions;
- planner-owned `NOT_APPLICABLE` decisions for non-intersecting pairs;
- `UNKNOWN` rather than optimistic omission when interface/extractor applicability is unresolved;
- a unique `focus_area_id` on every atomic check.

Python and C/C++ use the shared non-AI `JW-*` taxonomy; AI uses `AI-*`; Java, Web, and Platform use their direct catalog selectors. Every atomic subject/type/domain group must contain all three lenses.

Initialize the ledger once:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/initialize-coverage-ledger.mjs \
  --plan reports/coverage/coverage-plan.<audit-id>.json \
  --ledger reports/coverage/<audit-id>/ledger/coverage-ledger.jsonl
```

Coverage sessions never edit the plan or canonical ledger. Use the `coverage_ledger` MCP tools:

1. `coverage_get_packet` filtered by exact `audit_id`, `focus_area_id`, domain, and lens.
2. `coverage_inspect_subject` for each assigned check.
3. `coverage_record_tool_result` with frozen source hashes, concrete locators, exact query/rule, tool name, and result digest. The service creates the receipt. Catalog-domain checks freeze every source file owned by that domain (all scoped files for AI); the union of referenced receipts must cover that entire source set. Interface checks must cover their source file.
4. `coverage_submit_decision` with separate execution and result states.
5. `coverage_get_gaps` for follow-up routing.
6. `coverage_finalize` only after all required checks are verified.

Execution states are `PLANNED → INSPECTED → VERIFIED`, or terminally incomplete `GAP`/`INVALIDATED`. Result states are independently `NO_FINDING`, `FINDING`, or `INCONCLUSIVE`. `VERIFIED` requires a valid same-check receipt. `FINDING` requires finding IDs and closes only its atomic check; it never closes other types, interfaces, or lenses. Agents cannot submit `N/A`. Direct writes to `reports/coverage/<audit-id>/ledger/` are denied.

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

File evidence uses `kind=source-location` and must bind `file_id`, exact frozen `path`, `sha256`, and `line_start`. A scoped symlink instead uses `kind=symlink-location` with its `file_id`, path, and frozen `link_target`. Catalog evidence uses `kind=catalog-review` and must bind `catalog_id`, domain, lens, catalog profile, and the SHA-256 of its exact lens question. `FINDING` requires IDs present in the report's `findings`; `GAP` always prevents completion. The initializer's `assignment-anchor` is valid only while a row remains `GAP`.

## Verify before reporting

Seal `threat-model.json` and `focus-areas.json` with `seal-semantic-manifest.mjs`. Before final verification, run `snapshot-coverage-inputs.mjs` with `--interfaces`, `--interface-extractors`, `--threat-model`, and `--focus-areas` to copy them alongside the validated scope, every function manifest, and exact catalog into `reports/coverage/<audit-id>/inputs/`.

Run the legacy structural verifier into a non-authoritative intermediate artifact, finalize the Ledger, then run v2 as the authoritative structural/type/interface gate:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/verify-coverage.mjs \
  <all frozen v1 arguments> \
  --output reports/coverage/coverage-structural-v1.<audit-id>.json

# coverage_finalize is called through the coverage_ledger MCP service.

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/verify-coverage-v2.mjs \
  --audit-id <audit-id> \
  --plan reports/coverage/coverage-plan.<audit-id>.json \
  --ledger reports/coverage/<audit-id>/ledger/coverage-ledger.jsonl \
  --structural reports/coverage/coverage-structural-v1.<audit-id>.json \
  --output reports/coverage/coverage-verification.<audit-id>.json

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/render-coverage-summary.mjs \
  --plan reports/coverage/coverage-plan.<audit-id>.json \
  --ledger reports/coverage/<audit-id>/ledger/coverage-ledger.jsonl \
  --structural reports/coverage/coverage-structural-v1.<audit-id>.json \
  --output reports/coverage/coverage-summary.<audit-id>.json

node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/verify-coverage-summary.mjs \
  --summary reports/coverage/coverage-summary.<audit-id>.json \
  --plan reports/coverage/coverage-plan.<audit-id>.json \
  --ledger reports/coverage/<audit-id>/ledger/coverage-ledger.jsonl \
  --structural reports/coverage/coverage-structural-v1.<audit-id>.json
```

Also run `verify-semantic-coverage.mjs` with the snapshot index, vulnerability-mining reports directory, and final attack-chain report. A complete audit requires authoritative coverage v2, verified summary, and semantic artifacts to say `complete: true`.

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
10. The ledger hash chain, plan/scope binding, finalization event, and machine-derived summary are valid.

Semantic completion requires:

1. Every entry point has threats or evidence-backed deprioritization and no blocking open question remains.
2. Every threat maps to a Focus Area and has at least one complete owning Focus Area under every lens.
3. Every Focus Area primary assignment has one complete coverage report under all three lenses.
4. Every Focus Area has a valid blind artifact and every history-seeded area has a valid seeded-variant artifact.
5. The system attack-chain report accounts for every Focus Area, trust boundary, and asset.

Coverage metrics use `R=required`, `V=verified`, `U=unknown`, and `N=not applicable`. Known coverage is `V/R`; the conservative lower bound is `V/(R+U)`. `R=0` renders `NOT_APPLICABLE`, never 100%. Vulnerability-type and external-interface metrics report both atomic-check coverage and completely checked entities, by lens; interfaces also split ingress, egress, and bidirectional. Files are complete only when every required file record and contained function check is complete.

Each verifier exits nonzero on any violation. Only all three terminal gates authorize a complete structural/type/interface-and-semantic coverage statement.

## Claim boundary

The structural gate proves base-owner plus AI-overlay accounting over frozen files, source-defined functions, executable template units recognized by configured AST/CPG extractors, catalog domains, and deterministic source/spec/config external-interface anchors. Coverage v2 additionally proves execution of every frozen required vulnerability-type/interface/lens check with service-generated digest-bound receipts. These are coverage-completion claims, not proof that no vulnerability exists. The semantic gate proves terminal entry-point threat decisions, Focus Area/lens/track execution, and a system pass over declared boundaries/assets. Unsupported potential source, generated code absent from the repository, hosted model/tool behavior, and runtime-only controls remain gaps.
