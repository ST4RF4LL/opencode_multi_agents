# Joern Rules

Store Joern and CPG-based static-analysis rules here.

Recommended layout:

- `index.json`: inventory of rules.
- `<language>/<rule-id>.sc`: Joern query or script (CPG pre-loaded by MCP; no `importCpg` / `@main`).
- `<language>/<rule-id>.md`: rule intent, source/sink model, expected hits, known false positives, and test notes.

Rules should support defensive static analysis only.

## Java seed

105 rules promoted from `vuln_skill_builder` deep packs into `java/`, adapted for `joern_run_rule` (`language=java`, `rule_id=<id>` without `.sc`).
