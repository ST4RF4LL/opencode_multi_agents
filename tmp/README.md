# Temporary Audit Workspace

This directory is for per-task and per-agent-session runtime artifacts.

The orchestrator should clean this directory at the end of each audit task, preserving only `.gitkeep` and this README.

Expected runtime layout:

- `reports/sarif/<agent-name>.<agent-session-id>.sarif`
- `reports/vulnerability-mining/<agent-name>.<agent-session-id>.json`
- `work/<agent-name>/<agent-session-id>/`

Reusable scripts, rules, and cases should be promoted by `security-skill-optimizer` into `.opencode/skills/` or `.opencode/shared/security-audit/`, not kept here.
