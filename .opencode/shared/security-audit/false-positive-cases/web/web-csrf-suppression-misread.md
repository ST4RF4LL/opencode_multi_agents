# Web Counter-Evidence Pattern: CSRF Suppression (SameSite + Bearer + No CORS) Misread

**Dimension**: D9
**Lens**: control-driven
**Discovery Track**: coverage
**Threat/Focus**: T-07 | FA-INGRESS-AUTHN / FA-PLATFORM-DEPLOY

## Why Flagged (the counter-claim)

An auditor may argue a session-hijack or token-theft finding is a false positive because:

- `Set-Cookie: ...; SameSite=Lax` is present, so cross-site cookie submission is restricted.
- The API authenticates via `Authorization: Bearer` (header), and cross-site scripts cannot set custom headers without CORS preflight.
- No CORS headers are emitted, so cross-origin reads appear blocked.

## Why Safe (analysis — the claim fails to refute the finding)

- SameSite only governs *cookie* attachment to cross-site requests; it does nothing against **same-origin script execution** reading `localStorage` or a non-HttpOnly cookie (token theft, not cookie CSRF).
- The server's `readToken` accepts the `Authorization` header, which is **not affected by SameSite at all** — a stolen Bearer token replays from any context.
- SameSite=Lax does not stop top-level navigation flows or other CSRF shapes; more importantly, the reviewed findings were **token theft / XSS-driven session hijack**, not classic cookie-CSRF, so the CSRF mitigation is simply the wrong control class.
- Missing CORS headers block *reading* cross-origin responses, not *writing* simple requests; and it is a config gap (aggravator for T-07) rather than a mitigating control.

## Exclusion Rule

Treat `SameSite`/`Bearer`/`no-CORS` as a *limiting* observation only when the finding itself claims **classic cookie-CSRF** on a state-changing endpoint **and** the session cookie is HttpOnly + SameSite=Strict **and** a CSRF token/Origin check exists. For token-theft, XSS-amplification, and session-hijack findings, these controls never defeat the finding.

## Skill/Rule Adjustment

`web-source-security-review` (D9/D2): when evaluating session material findings, map the claimed mitigation to the attack class first (cookie CSRF vs token theft vs XSS chain). Record SameSite/Bearer/CORS as LIMITS evidence, never as a standalone false-positive reason. Cross-reference `false-positive-cases/web/web-csrf-suppression-misread.md`.

## Source

audit-20260812-rvi09 three-party review (negative role counter-claims refuted by moderator):
FA-INGRESS-AUTHN-SNK-03, FA-INGRESS-AUTHN-CTRL-02, FA-PLATFORM-DEPLOY-PCTRL-03.
