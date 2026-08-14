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

## Node.js / vanilla-JS server + SPA confirmed patterns

Confirmed by three-party review on a frozen `node:http` webapp (audit-20260812-rvi09, 67/67 TRUE_POSITIVE). Reusable cases: `.opencode/shared/security-audit/vulnerability-cases/web/`; counter-evidence patterns: `false-positive-cases/web/`; unvalidated rule gap list: `joern-rules/web/gaps.md`.

| Grep pattern | Judgment rule (confirm only when ALL conditions hold) | Tags |
|---|---|---|
| `token.split('.')` / `payload.split` / `Buffer.from(...,'base64url')` in an auth verifier | Token verification sink that never compares a keyed MAC and never enforces `exp` = complete auth bypass. Reversible base64url "signature" of payload+secret is secret disclosure, not a MAC. | T-01, FA-INGRESS-AUTHN, D2, sink-driven, coverage |
| `path.join(` + `writeFileSync` / `mkdirSync(...,{recursive:true})` with client filename | Attacker filename reaching `writeFileSync` without `normalize()+startsWith(baseDir)` = path-traversal write. `path.join` resolves `..` lexically; a prefix does not confine. If webroot is a cwd sibling, overwrite = stored-XSS to all visitors. | T-04, FA-FILE-WRITE, D5, sink-driven, coverage |
| `innerHTML = \`...\${` + `localStorage` token + no `Content-Security-Policy` | Unescaped server data into innerHTML + script-readable session material + no CSP = stored-XSS/token-theft chain (cross-lens: sink + config + storage). `textContent` on some sinks exempts none of the rest. | T-05, FA-BROWSER-DOM, D1, cross-lens, coverage |
| `data += chunk` in a body reader / `JSON.parse(data)` | Unbounded body accumulation with no byte cap or content-length pre-check = memory-exhaustion DoS; a pre-auth route reaching the parser makes it unauthenticated. Zero-dependency manifest = provable absence of middleware limits. | T-08, FA-PLATFORM-DEPLOY, D10, sink-driven, coverage |
| async handler with `writeFileSync`/`readFileSync` and no `try/catch`, no `process.on('unhandledRejection')` | Throwing sync I/O in an async handler + no exception boundary = one-request crash on Node >=15 (keep crash leg runtime-conditional). Fail-open `JSON.parse` catch (`{}`) is state confusion, not an error boundary. | T-08, FA-PLATFORM-DEPLOY, D9, control-driven, coverage |
| `pathname.split('/').pop()` → lookup by id → `res.json(rawRecord)` | Caller-supplied object id with no `session.id`/`ownerId` compare and no output projection = IDOR + raw sensitive-field disclosure. A redaction helper applied only on some endpoints is call-site selective, not a mitigation. | T-03, FA-INGRESS-AUTHZ, D3, sink-driven, coverage |
| `Set-Cookie` without `HttpOnly`/`Secure`; `listen(port)` without host/TLS; single `console.log`; only `Content-Type` set | Absence checks: cookie flags (D2), plaintext listener (D6/D7), audit logging (D8), security headers/CSP (D8) — each is a config-lens confirmatory fact with a negative-search requirement. | T-07/T-09, FA-INGRESS-AUTHN / FA-PLATFORM-DEPLOY, D2/D6/D8, config-driven, coverage |

## False-positive notes (web)

- **SameSite=Lax + Bearer + no CORS does not refute session-hijack/token-theft findings** — SameSite governs cookie attachment only; `Authorization`-header replay and same-origin script reads are unaffected. Map the claimed mitigation to the attack class before downgrading.
- **RFC 7234 cache semantics do not refute data-exposure findings** — cache-exclusion rules concern shared caches; missing `Cache-Control: no-store` on sensitive responses is an aggravator, not a mitigation.
- **Single-tenant ≠ IDOR N/A** — tenancy is the tenant boundary, not the principal boundary; user-to-user object reads remain authorization failures.
See `false-positive-cases/web/web-{csrf-suppression,rfc7234-cache-semantics,single-tenant-na}-misread.md`.

## Evidence and closure

Evidence should name file/function IDs, lines or symbols, inspected data/control/config relationships, and relevant inventory/catalog IDs. `N/A` requires an absence argument and search/scope evidence. A file/function with one identified finding still requires review of the remainder of that unit.

Use the trusted structural artifact for entity closure and the orchestrator-owned local audit-todo with accepted packet handoffs for scheduling closure; prose statements and aggregate counts are not substitutes.
