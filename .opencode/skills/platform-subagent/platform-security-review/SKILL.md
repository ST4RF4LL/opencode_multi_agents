---
name: platform-security-review
description: Tri-Lens review guidance for dependency, build, CI/CD, container, orchestration, gateway, secret, network, and IaC artifacts. Use when auditing language-neutral platform surfaces across D1-D10.
license: MIT
metadata:
  role: platform-security-auditor
  collection: platform-subagent
---

# Platform Security Review

Apply one assigned Tri-Lens strategy to platform artifacts. Distinguish repository evidence from deployed-state assumptions. Read the frozen scope and the versioned application/AI vulnerability catalog before review. Emit `domain=base` for file and function records.

## D1-D10 Platform Questions

| D# | Sink-driven anchors | Control-driven checks | Config-driven checks |
|----|---------------------|-----------------------|----------------------|
| D1 | Shell interpolation, templating, workflow expressions, build arguments | Quoting, allowlists, untrusted-event isolation, command boundaries | Shell mode, workflow permissions, templating options |
| D2 | Identity-provider, token, session, secret, and login endpoints/settings | MFA, token lifecycle, recovery, replay, workload identity | OIDC claims, token TTL, cookie/session, identity settings |
| D3 | Deploy, admin, secret, artifact, cluster, and cloud resource actions | Least privilege, role/tenant separation, approval, ownership | IAM/RBAC, service accounts, workflow permissions, gateway policy |
| D4 | Parser, decoder, package/plugin loader, untrusted artifact import | Provenance, signature, allowlist, isolation | Parser modes, plugin policy, serialization formats |
| D5 | Mounts, volumes, archive extraction, artifact upload/download, host paths | Path/type/size checks, read-only mounts, isolation, ownership | Filesystem permissions, volume policy, upload and temp settings |
| D6 | Egress, callbacks, proxies, health hooks, metadata access, public redirects | Scheme/host/IP/DNS restrictions, egress controls | Network policy, proxy, DNS, service mesh, metadata settings |
| D7 | TLS termination, certificates, KMS/secret operations, signing | Rotation, trust, nonce/key lifecycle, access separation | TLS versions/ciphers, KDF, certificate, KMS, signing policy |
| D8 | Public listeners, debug/admin endpoints, logs, environment/secret outputs | Auth, redaction, production guards, namespace isolation | Debug, CORS, TLS, logging, secret, hardening, privilege settings |
| D9 | Promotion, rollback, approval, scaling, destructive and financial jobs | State gates, separation of duties, idempotency, concurrency, limits | Environment gates, feature flags, quotas, policy-as-code |
| D10 | Package/image/plugin fetch and execution, build dependencies | Pinning, provenance, signing, SBOM, review and update process | Versions, digests, lockfiles, repositories, base images, plugins |

## Review Rules

1. Establish which environment or branch each file affects.
2. Resolve includes, overlays, values files, inherited workflow permissions, and variable precedence when possible.
3. Mark effective-state uncertainty as a gap when it changes the conclusion.
4. Correlate platform settings to consuming source components via artifact IDs; do not duplicate source findings.
5. For dependency findings, record package/image version, advisory basis, relevant feature/API, and reachability confidence.
6. For secret findings, redact values and report exposure paths, not secret contents.
7. Use `N/A` only after inspecting all applicable artifact classes in scope.
8. Traverse every scope record owned by `platform-security-auditor`, including unknown text, documentation, binary, and symlink records; do not sample.
9. Iterate every catalog entry whose `applies_to` contains `platform` using the assigned lens question.

## Output Requirements

Follow `secure-code-review-common`. Include one D1-D10 coverage cell for the assigned lens and platform-specific evidence fields:

```yaml
artifact_type: <ci|container|k8s|iac|gateway|dependency|build|secret-config>
environment: <dev|test|staging|prod|unknown>
effective_precedence: <evidence or unknown>
consuming_components: []
runtime_assumptions: []
```

Also emit exact `file_coverage` records and `catalog_coverage` records with `domain=platform`. Use the entry's declared dimensions for catalog records. Any unreadable or unreviewed item is `GAP` and prevents complete verification.
