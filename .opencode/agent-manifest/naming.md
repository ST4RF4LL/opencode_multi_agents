# Naming and Maintenance

## Skill naming

Use lowercase names with single hyphen separators. The skill directory name must match the `name` field in `SKILL.md`.

Project skills are grouped by owner:

`.opencode/skills/<subagent-skill-group>/<skill-name>/SKILL.md`

Example:

`.opencode/skills/c-cpp-subagent/c-cpp-vuln1-skill/SKILL.md`

Group directories such as `threat-modeling-subagent`, `c-cpp-subagent`, `java-subagent`, `web-subagent`, `python-subagent`, `platform-subagent`, `ai-subagent`, `attack-chain-subagent`, and `evidence-correlation-subagent` are collection directories, not OpenCode skills. They intentionally do not contain `SKILL.md`. Their `collection.json` files list the nested atomic skills that OpenCode can discover recursively.

Preferred prefixes:

- `recon-*`, `intel-*`, `dependency-intel-*`, `attack-surface-*` for information collection.
- `threat-*`, `evidence-backed-threat-*`, `focus-area-*` for threat modeling and discovery partitioning.
- `c-cpp-*`, `cpp-*`, `native-security-*`, `memory-safety-*` for C/C++ auditing.
- `java-*`, `jvm-*`, `spring-security-*`, `deserialization-*` for Java/JVM auditing.
- `web-*`, `javascript-*`, `typescript-*`, `browser-security-*` for Web source auditing.
- `python-*`, `py-*`, `django-security-*`, `flask-security-*`, `fastapi-security-*` for Python auditing.
- `platform-*`, `container-*`, `cicd-*`, `iac-*`, `supply-chain-*` for platform auditing.
- `ai-*`, `llm-*`, `agentic-*`, `rag-*`, `mcp-security-*` for AI system auditing.
- `tri-lens-*`, `evidence-correlation-*`, `coverage-*` for evidence correlation.
- `attack-chain-*`, `system-attack-*` for system-level chain discovery.
- `validation-*`, `poc-*`, `exploitability-*` for vulnerability validation.

When a new custom skill fits an existing group and prefix, add it under that group directory and update the group's `collection.json`. The skill auto-maps to the subagent via the `owner_agent` field in `collection.json`. Agent frontmatter uses `"*": allow` for skills, so no permission changes are needed.

When adding a skill to a collection, create the actual skill at `.opencode/skills/<subagent-skill-group>/<skill-name>/SKILL.md`, then add `<skill-name>` to the collection directory's `collection.json`.

## MCP naming

Name MCP servers by capability, not vendor, when they are private or replaceable. Exposed tools should be treated as `<server>_*` permission patterns.

Recommended server categories:

- `*_index` for code indexing and call graph tools.
- `*_scan` for static scanners.
- `*_intel` for external documentation, advisory, or code intelligence.
- `audit_lab` for safe local validation helpers.
- `joern` for CPG and Joern query workflows.

When replacing a placeholder MCP, keep the server name if possible so agent permissions do not need to change.

## Shared audit assets

Shared audit assets live under `.opencode/shared/security-audit/` and are readable by all subagents:

- `joern-rules/` for Joern rules and rule metadata.
- `vulnerability-cases/` for confirmed vulnerability examples that should improve skills and rules.
- `false-positive-cases/` for rejected findings and suppressions that should reduce repeated false positives.
- `rule-results/` for non-source transient/static-scan summaries that help optimization.
- `catalogs/` for versioned vulnerability coverage catalogs and lens questions.

Only `security-skill-optimizer` should modify these assets during normal audit feedback loops.

## Temporary artifacts and durable reports

All temporary files belong under root `tmp/`, not under `.opencode/shared/`.

All durable audit deliverables belong under workspace-root `reports/` only. Never write final reports under `tmp/` or inside audited application/test source trees outside `reports/`.

- Final human-readable audit report: `reports/final/security-audit-report.<audit-id>.md`
- Static-analysis reports use SARIF 2.1.0 at `reports/sarif/<agent-name>.<agent-session-id>.sarif`.
- Vulnerability-mining reports use JSON at `reports/vulnerability-mining/<agent-name>.<agent-session-id>.audit-report.json`.
- Blind/seeded discovery reports use JSON at `reports/vulnerability-mining/<agent-name>.<agent-session-id>.discovery.json`.
- System attack-chain reports use JSON at `reports/attack-chains/security-attack-chain-hunter.<audit-id>.r<round>.json`.
- Correlation reports use JSON at `reports/correlation/security-evidence-correlator.<audit-id>.r<round>.json`.
- Final coverage verification uses JSON at `reports/coverage/coverage-verification.<audit-id>.json`.
- Final semantic verification uses JSON at `reports/coverage/semantic-coverage-verification.<audit-id>.json`.
- Recon inventories and scratch data use `tmp/<audit-id>/`.

Agents must **not** automatically delete `tmp/` or `tmp/<audit_id>/`. Temporary workspace cleanup is manual-only after a human confirms durable `reports/**` deliverables are retained. Reusable scripts, rules, cases, or skill improvements must still be promoted by `security-skill-optimizer` out of `tmp/` into `.opencode/skills/` or `.opencode/shared/security-audit/`.
