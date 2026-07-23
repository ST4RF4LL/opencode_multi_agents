# Temporary Audit Workspace

This directory is for per-audit runtime reconnaissance and scratch artifacts.

**Do not auto-delete this directory.** Agents must not remove `tmp/` or any `<audit-id>/` subdirectory at task end. Cleanup is manual-only after a human confirms durable deliverables under `reports/` are retained.

Expected runtime layout:

- `<audit-id>/recon/` — entry-point, sink, sensitive-operation, config-surface, AI-surface, recon-summary, sealed threat-model, and sealed Focus Area JSON artifacts
- `<audit-id>/recon/coverage/` — frozen recursive scope plus complete AST/CPG function manifests
- `<audit-id>/` — follow-up packets, scratch files, generated scripts, intermediate rules, and tool raw output

Durable final report, coverage/discovery sessions, system attack-chain reports, SARIF, correlation, snapshots, and dual coverage verification artifacts are stored in the workspace-root `reports/` directory, not under `tmp/` and not inside audited application/test source trees.

Reusable scripts, rules, and cases should be promoted by `security-skill-optimizer` into `.opencode/skills/` or `.opencode/shared/security-audit/`, not kept here.
