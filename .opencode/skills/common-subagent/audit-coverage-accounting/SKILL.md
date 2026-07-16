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
  --output tmp/<audit-id>/coverage/scope-manifest.json
```

The scope builder walks the filesystem rather than only tracked files. It excludes only audit infrastructure and VCS internals, records every exclusion, hashes every file, assigns an owner, and marks which parser must inventory functions.

## Inventory Java functions

```sh
node .opencode/skills/common-subagent/audit-coverage-accounting/scripts/build-java-function-manifest.mjs \
  --root . \
  --audit-id <audit-id> \
  --scope tmp/<audit-id>/coverage/scope-manifest.json \
  --output tmp/<audit-id>/coverage/functions-java.json
```

This uses the JDK compiler AST, not regex. It inventories explicit methods, constructors, lambdas, and class initializer blocks. Any parse error or missing Java file makes the manifest incomplete and the command fail after writing diagnostics.

For JavaScript, Python, C/C++, Kotlin, and other JVM source tagged by the scope builder, use `build-joern-function-manifest.mjs --language <javascript|python|c|cpp|kotlin|jvm>`. For JSP/HTML/template inline scripts and macros, use `build-embedded-web-manifest.mjs`. Every `function_inventory_required` file must occur in exactly one complete function manifest.

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
