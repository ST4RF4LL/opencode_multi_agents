---
name: java-web-comprehensive-review
description: Deterministic Java/JVM and server-side Web review across every scoped file and AST/CPG function, D1-D10, all three separately assigned lenses, and the unified application/AI vulnerability catalog. Use as the mandatory umbrella skill for Java audit sessions before loading weakness-specific packs.
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
---

# Java Web Comprehensive Review

This is the coverage backbone for Java/JVM audits. Use one assigned lens per session and progressively load weakness-specific skills for depth.

## Inputs and traversal

Require the frozen scope manifest, the complete Java/JVM function manifests, Recon inventories, and `.opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json`. Emit `domain=base` for file and function coverage records.

1. Select every file record owned by `java-source-auditor`.
2. Require exactly one complete AST/CPG manifest membership for every function-bearing file.
3. Review every file and every inventoried method, constructor, lambda, initializer, nested/anonymous-class function, Kotlin/JVM function, and program unit.
4. Apply the assigned lens across D1-D10 to every unit.
5. Iterate every catalog entry applicable to `java`, following `sink_question`, `control_question`, or `config_question` according to the assigned lens.
6. Emit exact `file_coverage`, `function_coverage`, and `catalog_coverage` records. Never infer coverage from aggregate query counts.

Any missing parser output, unreadable file, unexplored generated/runtime path, or skipped unit is a `GAP`. A finding does not close the rest of a file or function. `N/A` needs concrete scope and absence evidence.

## Catalog domains that must not be lost

In addition to the existing injection/deserialization/SSRF/path/crypto packs, explicitly cover:

- object, function, property, and tenant authorization
- login, session, JWT, OAuth/OIDC/SAML, MFA, recovery, and credential abuse
- header/cookie/log injection, template/EL/OGNL/code evaluation, JNDI and unsafe lookups
- CSRF, CORS, CSP/clickjacking, request smuggling, cache poisoning, GraphQL, WebSocket, SSE and alternate transports
- TLS/trust, secret/data exposure, exception/fail-open behavior, transaction rollback, resilience, DoS and ReDoS
- sensitive business flows, race/replay/idempotency, state machines, quotas and resource consumption
- integrity/update/plugin loading, dependency/build/image supply chain, debug/management exposure, and API inventory drift

If no specialized deep pack exists, perform the review directly from the catalog questions and record a learning candidate for later skill optimization. Do not mark the catalog entry `N/A` merely because no deep pack exists.

## Closure records

File and function records must list all `D1` through `D10` in `dimensions_reviewed`. Catalog records use the dimensions declared by that catalog entry and `domain=java`. All records cite concrete evidence and are validated by intermediate `verify-coverage.mjs`; complete claims additionally require receipt-backed Coverage Ledger packets and `verify-coverage-v2.mjs`.
