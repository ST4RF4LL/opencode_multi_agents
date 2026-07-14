# java-weak-cryptography-source-to-sink

- **language**: java
- **skill**: `java-weak-cryptography`
- **weakness**: `weak-cryptography`
- **dimension**: D7
- **source_script**: `skills/java-subagent/java-weak-cryptography/rules/joern/source-to-sink.sc`
- **adapted_for_mcp**: True
- **params**: ['cpgFile: String']

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern_create_cpg` for the target Java sources.
2. `joern_run_rule` with `language=java`, `rule_id=java-weak-cryptography-source-to-sink`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
