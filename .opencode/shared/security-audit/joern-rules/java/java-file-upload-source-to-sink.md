# java-file-upload-source-to-sink

- **language**: java
- **skill**: `java-file-upload`
- **weakness**: `file-upload`
- **dimension**: D5
- **source_script**: `skills/java-subagent/java-file-upload/rules/joern/source-to-sink.sc`
- **adapted_for_mcp**: True

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern_create_cpg` for the target Java sources.
2. `joern_run_rule` with `language=java`, `rule_id=java-file-upload-source-to-sink`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
