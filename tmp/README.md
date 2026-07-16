# Temporary Audit Workspace

This directory is for per-audit runtime reconnaissance and scratch artifacts.

The orchestrator should clean only the current audit-id subdirectory at the end of each audit task, preserving `.gitkeep` and this README.

Expected runtime layout:

- `<audit-id>/recon/` — entry-point, sink, sensitive-operation, config-surface, AI-surface, recon-summary, sealed threat-model, and sealed Focus Area JSON artifacts
- `<audit-id>/recon/coverage/` — frozen recursive scope plus complete AST/CPG function manifests
- `<audit-id>/` — follow-up packets, scratch files, generated scripts, intermediate rules, and tool raw output

Durable coverage/discovery sessions, system attack-chain reports, SARIF, correlation, snapshots, and dual coverage verification artifacts are stored in the `reports/` directory at the project root, not under `tmp/`.

Reusable scripts, rules, and cases should be promoted by `security-skill-optimizer` into `.opencode/skills/` or `.opencode/shared/security-audit/`, not kept here.
