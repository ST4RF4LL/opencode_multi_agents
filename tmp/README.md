# Temporary Audit Workspace

This directory is for per-task runtime scratch artifacts.

The orchestrator should clean only the task subdirectories at the end of each audit task, preserving `.gitkeep` and this README.

Expected runtime layout:

- `<task-module>/` — scratch files, generated scripts, intermediate rules, and tool raw output

Audit reports (SARIF, JSON) are stored in the `reports/` directory at the project root, not under `tmp/`.

Reusable scripts, rules, and cases should be promoted by `security-skill-optimizer` into `.opencode/skills/` or `.opencode/shared/security-audit/`, not kept here.
