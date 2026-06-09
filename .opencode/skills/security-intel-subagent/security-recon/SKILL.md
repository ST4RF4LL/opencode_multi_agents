---
name: security-recon
description: Build an attack-surface and language-routing map for source security audits before deep code review.
license: MIT
compatibility: opencode
metadata:
  role: security-intel-collector
  phase: reconnaissance
---

# Security Recon

Use this skill before source review to create a factual map of the project.

## Checklist

- Identify languages, frameworks, build systems, package managers, and generated/vendor directories.
- Locate entrypoints: HTTP routes, RPC handlers, CLI commands, background jobs, message consumers, parsers, native bindings, plugins, and admin surfaces.
- Locate trust boundaries: unauthenticated input, authenticated user input, admin input, file/network/process boundaries, IPC, and cross-tenant boundaries.
- Locate sensitive assets: secrets, tokens, credentials, keys, PII, privileged operations, filesystem access, and network access.
- Inspect dependency manifests and lockfiles for risky package families or stale security-critical dependencies.
- Record deployment hints from Dockerfiles, CI files, IaC, service configs, environment variable names, and default config files.

## Output Contract

Return an `Attack Surface Map` and `Language Audit Routing` table. Do not overstate vulnerabilities; flag suspicious areas as audit targets unless direct source evidence proves a finding.
