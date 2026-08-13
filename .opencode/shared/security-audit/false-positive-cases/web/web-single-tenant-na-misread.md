# Web Counter-Evidence Pattern: Single-Tenant N/A Misread

**Dimension**: D3
**Lens**: control-driven
**Discovery Track**: coverage
**Threat/Focus**: T-03 | FA-INGRESS-AUTHZ

## Why Flagged (the counter-claim)

An auditor may argue an IDOR/BOLA finding is not applicable because "the application is single-tenant" — i.e., tenant-isolation / cross-tenant data-access reasoning does not apply, so object-level authorization findings are N/A.

## Why Safe (analysis — the claim fails to refute the finding)

- "Single-tenant" addresses **cross-tenant** separation only. IDOR findings here concern **user-level horizontal privilege escalation within one deployment**: any authenticated user reading another user's profile, orders, and payment data is a cross-*user* authorization failure, which exists independently of tenancy.
- The data model carries a `role` claim and per-user `ownerId` fields — evidence that per-user and per-role authorization were intended; single-tenancy does not remove the requirement to scope reads by principal.
- Impact is tenant-local but still real: full credential store and payment data are disclosed to any authenticated customer.
- The N/A argument also fails because the audited surface is not multi-tenant-aware at all — the absence of a tenant concept does not make object-level access control unnecessary; it makes the user the tenant boundary.

## Exclusion Rule

A single-tenant N/A argument is valid **only** when the finding's claim is explicitly cross-tenant data access (e.g., "tenant B can read tenant A's data") in an architecture that truly has no multi-tenant data model **and** no per-user object ownership concept. When the finding is user-to-user IDOR, per-role vertical escalation, or raw-record disclosure, tenancy is irrelevant — record the N/A claim as LIMITS evidence only.

## Skill/Rule Adjustment

`web-source-security-review` (D3): require auditors to separate "tenant boundary" from "principal boundary". A single-tenant deployment still requires object-level authorization between principals; tenant-absence is not an authorization-absence justification. Cross-reference `false-positive-cases/web/web-single-tenant-na-misread.md`.

## Source

audit-20260812-rvi09 three-party review deliberation (object-level authorization findings:
FA-INGRESS-AUTHZ-CTRL-02, FA-INGRESS-AUTHZ-CTRL-03, FA-INGRESS-AUTHZ-CFG-02, FA-INGRESS-AUTHZ-CFG-03).
