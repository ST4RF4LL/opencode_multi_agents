# java-sql-injection-locate-sinks

- **language**: java
- **skill**: `java-sql-injection`
- **weakness**: `sql-injection`
- **dimension**: D1
- **source_script**: `skills/java-subagent/java-sql-injection/rules/joern/locate-sinks.sc`
- **adapted_for_mcp**: True
- **params**: ['cpgFile: String']

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern_create_cpg` for the target Java sources.
2. `joern_run_rule` with `language=java`, `rule_id=java-sql-injection-locate-sinks`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
