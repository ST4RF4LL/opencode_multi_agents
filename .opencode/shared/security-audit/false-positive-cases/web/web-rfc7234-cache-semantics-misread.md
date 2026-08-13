# Web Counter-Evidence Pattern: RFC 7234 Cache Semantics Misread

**Dimension**: D8
**Lens**: config-driven
**Discovery Track**: coverage
**Threat/Focus**: T-06 / T-03 | FA-INGRESS-AUTHZ / FA-PLATFORM-DEPLOY

## Why Flagged (the counter-claim)

An auditor may argue a sensitive-data-exposure finding is weakened because, per RFC 7234, shared caches must not store responses to requests carrying an `Authorization` header (and heuristically should not store responses to cookie-authenticated requests), so "responses without Authorization are not cached" means the data does not leak through shared caches.

## Why Safe (analysis — the claim fails to refute the finding)

- RFC 7234 cache-exclusion rules govern *shared-cache* behavior, not the exposure itself: the disclosure exists at the API/IDOR layer regardless of any cache.
- The reviewed findings were **authorization failures** (IDOR raw-record disclosure, admin dump without role check, plaintext credential storage), not cache-poisoning or cache leakage claims — caching semantics are orthogonal to the confirmed root cause.
- Absence of `Cache-Control: no-store` / `Pragma: no-cache` on sensitive JSON responses is an **aggravating config gap** (private browser caches, proxies, and user agents may store responses), never a mitigating control.
- Whether any deployment adds a caching layer is deployment-unknown; the code-level disclosure is unconditional.

## Exclusion Rule

RFC 7234 reasoning is a valid *limiting* observation only for a finding whose claimed impact specifically depends on **shared-cache storage of authenticated responses** (cache-poisoning, cached-credential leakage). For IDOR, missing-authorization, and at-rest-plaintext findings, cache semantics never refute the finding; the absent `no-store` directive remains a config-lens aggravator.

## Skill/Rule Adjustment

`web-source-security-review` (D8): when a sensitive response is returned without `Cache-Control: no-store`, record the header absence as an aggravating config facet; do not let RFC 7234 default semantics downgrade an authorization finding. Cross-reference `false-positive-cases/web/web-rfc7234-cache-semantics-misread.md`.

## Source

audit-20260812-rvi09 three-party review deliberation (sensitive-response serialization paths:
FA-INGRESS-AUTHZ-CFG-04, FA-INGRESS-AUTHZ-SNK-05, FA-PLATFORM-DEPLOY-PCTRL-02).
