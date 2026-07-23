---
name: secure-code-review-common
description: Universal threat-led Focus Area Tri-Lens secure-code-review methodology. Use for every source, platform, or AI coverage audit to examine each applicable D1-D10 dimension with sink-driven, control-driven, and config-driven evidence while preserving threat, Focus Area, provenance, and gap rules.
license: MIT
metadata:
  role: shared
  collection: common-subagent
---

# Secure Code Review Common

Use this skill as the mandatory base methodology for source and platform security audits. Language- and platform-specific skills extend it with concrete patterns.

## Tri-Lens Audit Model

Apply all three lenses to every applicable D1-D10 dimension. Treat the lens as an execution mode, not as exclusive ownership of a vulnerability class.

| Lens | Core question | Required evidence | Key metric |
|------|---------------|-------------------|------------|
| **sink-driven** | What security-sensitive operation exists, and can untrusted influence reach it? | Anchor inventory, reachability/data-flow trace, guards encountered | Reviewed anchors / discovered anchors |
| **control-driven** | Which required security control is present or absent around each sensitive operation? | Operation inventory, expected control, implementation evidence or explicit absence | Reviewed operations / discovered operations |
| **config-driven** | Which effective setting, dependency, or deployment choice changes exploitability? | Config surface, effective value and precedence, baseline comparison | Reviewed config items / discovered config items |

Do not force every finding to contain three positive evidence facets. Coverage is Tri-Lens; individual findings may originate from one lens and gain supporting or mitigating evidence from the others.

## D1-D10 Tri-Lens Questions

| D# | Dimension | Sink-driven | Control-driven | Config-driven |
|----|-----------|-------------|----------------|---------------|
| D1 | Injection | Trace input to query, command, expression, template, or response sinks | Verify parameterization, validation, encoding, and authorization | Check ORM, template, parser, shell, and framework modes |
| D2 | Authentication | Locate token, password, session, MFA, and recovery operations | Verify lifecycle, replay, fixation, rate-limit, and bypass controls | Check JWT/OAuth/session/cookie/identity-provider settings |
| D3 | Authorization | Inventory sensitive resource operations | Verify role, tenant, ownership, and CRUD consistency | Check annotations, ACL, gateway, route, and policy configuration |
| D4 | Unsafe Data/Object Processing | Trace untrusted bytes/objects into decoders, loaders, native parsers, and memory operations | Verify type allowlists, bounds/lifetimes, signatures, provenance, and isolation | Check polymorphism, safe loaders, serializers, parser flags, and native hardening |
| D5 | File Operations | Trace names/content into read, write, upload, extract, or execute operations | Verify path, ownership, type, quota, and isolation controls | Check directories, permissions, size/type limits, and mounts |
| D6 | SSRF / Network | Trace attacker-influenced destinations into clients or redirects | Verify scheme, host, IP, DNS, redirect, and egress controls | Check proxies, network policies, metadata access, and client options |
| D7 | Cryptography | Locate security-sensitive crypto, randomness, key, and TLS APIs | Verify key lifecycle, nonce uniqueness, rotation, and trust decisions | Check algorithms, modes, KDF parameters, certificates, and TLS policy |
| D8 | Configuration | Locate exposed endpoints, logs, error responses, and secret consumers | Verify authentication, redaction, isolation, and production guards | Compare debug, CORS, TLS, logging, secret, and hardening settings |
| D9 | Business Logic | Inventory state-changing, financial, approval, batch, and export operations | Verify state transitions, invariants, idempotency, limits, and concurrency | Check limits, feature flags, tenant policy, and workflow configuration |
| D10 | Supply Chain | Determine whether vulnerable package APIs, plugins, or build steps are reachable | Verify pinning, provenance, signing, update, and review controls | Check versions, lockfiles, repositories, images, plugins, and build inputs |

## Work-Packet Contract

Require one `audit_strategy` per agent session:

```yaml
audit_id: <stable audit id>
agent_session_id: <language-focus-lens-coverage-round>
round: <positive integer>
threat_model: <sealed path>
focus_areas: <sealed path>
focus_area_id: <FA-id>
discovery_track: coverage
entry_point_ids: []
threat_ids: []
trust_boundary_ids: []
asset_ids: []
scope_manifest: <path>
scope_digest: <sha256>
assigned_file_ids: []
function_manifests: []
assigned_function_ids: []
catalog_profile: <profile id>
catalog_domain: <java|web|platform|null>
assigned_catalog_ids: []
language: <c-cpp|java|web|python|platform>
audit_strategy: <sink-driven|control-driven|config-driven>
dimensions: [D1, D2, D3, D4, D5, D6, D7, D8, D9, D10]
inventory_refs:
  entry_points: <path>
  sinks: <path>
  sensitive_operations: <path>
  config_surfaces: <path>
previous_gaps: []
depth: <quick|standard|deep>
```

Do not blend multiple strategies or Focus Areas in one coverage session. If the packet omits sealed semantic inputs, `focus_area_id`, `discovery_track=coverage`, exact primary assignments, or one unambiguous `audit_strategy`, return a protocol `GAP` and request a corrected packet. Blind/seeded packets use `focus-area-vulnerability-discovery` and never close this contract.

## Coverage-Cell Contract

Return exactly one cell for each requested `dimension` under the assigned lens.

```json
{
  "scope": "service-a",
  "language": "java",
  "dimension": "D3",
  "lens": "control-driven",
  "status": "PASS",
  "targets_discovered": 12,
  "targets_reviewed": 12,
  "evidence": ["src/...:42"],
  "finding_ids": [],
  "gap_reason": null,
  "na_reason": null
}
```

Use only these states:

- `PASS`: all discovered/in-scope targets were reviewed and no candidate remains.
- `FINDING`: coverage is complete and at least one candidate remains.
- `GAP`: any assigned target, inventory area, or required evidence remains unreviewed. `GAP` takes precedence even when findings exist.
- `N/A`: the dimension/lens is genuinely inapplicable, with scope and search evidence proving why.

Never translate “no grep hit” directly into `PASS` or `N/A`. State the searched scope, patterns or inventory, and limitations.

## Coverage Gate

Build semantic coverage over `Focus Area × Threat × Language/Domain × D1-D10 × Lens` and accounting coverage over every primary file, function, and applicable catalog-domain item × Lens. Do not average away a weak lens:

```text
dimension_coverage = min(sink_coverage, control_coverage, config_coverage)
```

Before REPORT:

1. Every assigned cell has `PASS`, `FINDING`, `GAP`, or evidence-backed `N/A`.
2. No unresolved `GAP` is hidden by a finding in the same cell.
3. D1, D2, and D3 have terminal cells for all three lenses.
4. Duplicate candidates across lenses are correlated into one canonical finding.
5. `verify-coverage.mjs` reports no missing, invalid, conflicting, parser, or scope-drift item.
6. `verify-semantic-coverage.mjs` reports no entry-point threat, Focus Area/lens/track, or system-pass gap.

The machine gate proves exact accounting over a frozen manifest. It does not prove that every possible vulnerability was recognized.

## Finding Evidence

Every candidate must include:

1. Affected code/config with real `file:line` evidence.
2. `dimension` and originating `lens`.
3. `focus_area_id`, related `threat_ids`, and discovery track.
4. Relevant facets: `sink_evidence`, `control_evidence`, and/or `config_evidence`.
5. Reachability, attacker influence, guards, provenance, and residual uncertainty.
6. Severity rationale: `Reachability × InputControl × ExploitComplexity × Impact`.
7. A concrete remediation.

## False-Positive Controls

- Confirm the file and location before reporting.
- Confirm the language, framework, feature, and deployment mode are actually used.
- Treat user-controlled configuration as a vulnerability only when it changes a reachable security boundary.
- Record sanitizers, authorization checks, feature flags, environment overrides, and dead-code conditions.
- Do not infer that a missing control is absent until the relevant operation inventory and inherited/global controls were checked.

## Session Output

```markdown
=== HEADER START ===
AUDIT_STRATEGY: sink-driven|control-driven|config-driven
FOCUS_AREA: FA-...
DISCOVERY_TRACK: coverage
COVERAGE: D1=PASS(N/N) | D2=N/A(evidence) | ... | D10=GAP(N/M)
GAPS: D#:[area]:reason
STATS: targets=N/M | files_read=N | tool_inputs=N
=== HEADER END ===

=== TRANSFER BLOCK START ===
FILES_READ: file:conclusion
SEARCH_DONE: pattern-or-query
HOTSPOTS: file:line:description
NEXT_GAPS: dimension:lens:target
=== TRANSFER BLOCK END ===
```

Also emit the `*.audit-report.json` required by `artifact-policy.json`, including `round`, frozen scope digest, sealed semantic input references, `focus_area_id`, `discovery_track=coverage`, `audit_strategy`, `coverage_cells`, exact `file_coverage`, `function_coverage`, `catalog_coverage`, `findings`, `artifacts`, and `learning_candidates`. File/function records must explicitly identify `domain=base` or the independent `domain=ai` overlay.

Populate `review_depth` with actual files/functions read, data/call paths expanded, and searches executed. The semantic verifier may flag suspiciously shallow activity, but review-depth counts never close a cell and never replace AST/CPG accounting.
