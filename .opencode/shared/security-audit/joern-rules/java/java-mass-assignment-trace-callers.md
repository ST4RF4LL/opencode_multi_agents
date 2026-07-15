# java-mass-assignment-trace-callers

- **language**: java
- **skill**: `java-mass-assignment`
- **weakness**: `mass-assignment`
- **dimension**: D9
- **source_script**: `skills/java-subagent/java-mass-assignment/rules/joern/trace-callers.sc`
- **adapted_for_mcp**: True

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern_create_cpg` for the target Java sources.
2. `joern_run_rule` with `language=java`, `rule_id=java-mass-assignment-trace-callers`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
