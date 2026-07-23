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

Structural and semantic completion are separate gates. Neither can substitute for the other.

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

Build the compact entity index used by threat modeling:

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-threat-routing-index.mjs \
  --audit-id <audit-id> \
  --scope tmp/<audit-id>/recon/coverage/scope-manifest.json \
  --functions tmp/<audit-id>/recon/coverage/functions-java.json \
  --functions tmp/<audit-id>/recon/coverage/functions-javascript.json \
  --functions tmp/<audit-id>/recon/coverage/functions-embedded-web.json \
  --catalog .opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json \
  --output tmp/<audit-id>/recon/coverage/threat-routing-index.json
```

Repeat `--functions` for additional languages. The routing index strips hashes, repeated lens metadata, and extractor internals while preserving every file/function/catalog ID needed for exact Focus Area assignment. Threat modeling should consume it plus the normalized Recon inventories, not the full structural manifests.

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

Repeat `--functions` for every manifest. The initializer validates the sealed threat/Focus artifacts, selects the exact primary assignment for the agent and Focus Area, sets `discovery_track=coverage`, and creates every required row as `GAP`. Auditors close rows with evidence; do not rebuild or shorten the arrays manually.

For `ai-security-auditor`, also pass `--ai-surfaces tmp/<audit-id>/recon/ai-surfaces.json`. Each initializer call selects one `domain=ai` Focus Area assignment; their union must equal every reviewable file, every inventoried function, and every AI catalog item.

For a later gap round, either repeat `--file-id`, `--function-id`, and `--catalog-id`, or pass `--assignment <json>`. The subset must remain inside the original Focus Area assignment. Without a follow-up assignment, the initializer uses the Focus Area's complete primary assignment. The structural verifier retains earlier-round records for entity/lens keys not present in a later subset report.

Name every single-lens report `*.audit-report.json` and include `round`, one canonical `audit_strategy`, all D1-D10 dimensions, the frozen scope digest, and:

- `focus_area_id` and `discovery_track=coverage`.

- `file_coverage`: one entry for every assigned file ID. Base owner sessions use `domain=base`; the AI overlay uses `domain=ai`.
- `function_coverage`: one entry for every assigned function ID with the same explicit base/AI domain rule.
- `catalog_coverage`: one entry for every required unified application/platform/AI catalog ID.

Catalog records include `domain=java`, `domain=web`, `domain=platform`, or `domain=ai`. When a catalog entry applies to multiple active domains, each domain owner reviews it independently.

Use `REVIEWED`, `FINDING`, `GAP`, or evidence-backed `N/A`. A reported finding never closes a remaining gap.

Record shape:

```json
{
  "function_id": "function:<stable-id>",
  "domain": "base",
  "status": "REVIEWED",
  "dimensions_reviewed": ["D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"],
  "evidence": [{"path": "src/...", "qualified_name": "Example.method"}],
  "finding_ids": []
}
```

File records use `file_id` and the same D1-D10 list. Catalog records use `catalog_id`, `domain`, and exactly the entry's declared dimensions. `FINDING` requires IDs present in the report's `findings`; `N/A` requires `na_reason`; `GAP` always prevents completion.

## Verify before reporting

Seal `threat-model.json` and `focus-areas.json` with `seal-semantic-manifest.mjs`. Before final verification, run `snapshot-coverage-inputs.mjs` with `--threat-model` and `--focus-areas` to copy them alongside the validated scope, every function manifest, and exact catalog into `reports/coverage/<audit-id>/inputs/`.

Run `verify-coverage.mjs` for structural accounting and `verify-semantic-coverage.mjs` with the snapshot index, vulnerability-mining reports directory, and final attack-chain report. A complete audit requires both artifacts to say `complete: true`.

Structural completion requires:

1. No scope drift: current file hashes equal the scope manifest.
2. No unreadable or unassigned files.
3. No parser errors or missing function-bearing files.
4. Every required file and function has both base-owner and independent AI-overlay records for all three lenses.
5. Every required catalog item has all three lens records for each applicable active domain, including AI.
6. No `GAP`, invalid `N/A`, unknown IDs, or conflicting ownership remains.

Semantic completion requires:

1. Every entry point has threats or evidence-backed deprioritization and no blocking open question remains.
2. Every threat maps to a Focus Area and has at least one complete owning Focus Area under every lens.
3. Every Focus Area primary assignment has one complete coverage report under all three lenses.
4. Every Focus Area has a valid blind artifact and every history-seeded area has a valid seeded-variant artifact.
5. The system attack-chain report accounts for every Focus Area, trust boundary, and asset.

Each verifier exits nonzero on any violation. Only both `complete: true` artifacts authorize a complete structural-and-semantic coverage statement.

## Claim boundary

The structural gate proves base-owner plus AI-overlay accounting over frozen files, source-defined functions, executable template units recognized by configured AST/CPG extractors, and catalog domains. The semantic gate proves terminal entry-point threat decisions, Focus Area/lens/track execution, and a system pass over declared boundaries/assets. Neither proves that every possible threat or vulnerability was recognized. Unsupported potential source, generated code absent from the repository, hosted model/tool behavior, and runtime-only controls remain gaps; never convert them to complete coverage.
