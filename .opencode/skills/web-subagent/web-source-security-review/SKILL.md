---
name: web-source-security-review
description: Deterministic Tri-Lens review of browser JavaScript/TypeScript and server-rendered Web templates across all scoped files, functions, D1-D10, and the unified application/AI vulnerability catalog. Use for JS/TS, HTML, JSP, FreeMarker, Velocity, Handlebars, Vue, Svelte, and related browser assets.
license: MIT
metadata:
  role: web-source-auditor
  collection: web-subagent
---

# Web Source Security Review

Use one assigned lens only. Read the frozen scope, complete `javascript` and `embedded-web` function manifests, and the versioned application/AI vulnerability catalog before reviewing source. Emit `domain=base` for file and function records.

## Deterministic traversal

1. Select every scope record owned by `web-source-auditor`; do not sample by directory or extension.
2. Match every file requiring function inventory to exactly one complete function manifest.
3. Review every file and every inventoried program, function, method, lambda, template macro, JSP block, and inline-script unit.
4. Iterate every catalog entry applicable to `web` with the assigned lens question.
5. Write exact file, function, and catalog coverage records. Any unreadable, unsupported, or skipped unit remains `GAP`.

## D1-D10 browser/template interpretation

| D# | Required Web focus |
|----|--------------------|
| D1 | DOM/template/script/style/URL injection, prototype pollution, unsafe parsing and dynamic evaluation |
| D2 | Login/session/token/OAuth flows, browser credential storage, fixation, leakage and invalidation |
| D3 | Client-only access controls, object/property/function authorization assumptions, tenant/role UI behavior |
| D4 | Unsafe JSON/YAML/XML/message parsing, polymorphic data handling, dynamic module/artifact loading |
| D5 | Upload/download/preview paths, filename/content handling, local file APIs and archive workflows |
| D6 | Redirect/navigation, URL construction, proxy/fetch destinations, WebSocket/SSE endpoints and DNS/origin assumptions |
| D7 | WebCrypto use, randomness, TLS assumptions, key/token handling, signature verification and trust decisions |
| D8 | CSP/CORS/headers/cookies/source maps/debug/errors/logging/caches/service workers/environment exposure |
| D9 | CSRF, race/replay/idempotency, state transitions, price/quantity/limit trust, batch/export and sensitive flows |
| D10 | npm/package/build/CDN/remote script integrity, lifecycle scripts, locks, dynamic imports and provenance |

For controls that only a server can enforce, verify the paired server operation through Recon/correlation evidence. Browser-side hiding or validation never proves authorization or integrity.

## Evidence and closure

Evidence should name file/function IDs, lines or symbols, inspected data/control/config relationships, and relevant inventory/catalog IDs. `N/A` requires an absence argument and search/scope evidence. A file/function with one identified finding still requires review of the remainder of that unit.

Use `verify-coverage.mjs` for intermediate entity closure and the finalized Coverage Ledger plus `verify-coverage-v2.mjs` as the authoritative closure authority; prose statements and aggregate counts are not substitutes.
