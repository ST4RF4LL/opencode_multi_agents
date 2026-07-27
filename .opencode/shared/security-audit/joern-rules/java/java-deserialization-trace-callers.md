# java-deserialization-trace-callers

- **language**: java
- **skill**: `java-deserialization`
- **weakness**: `deserialization`
- **dimension**: D4
- **source_script**: `skills/java-subagent/java-deserialization/rules/joern/trace-callers.sc`
- **execution**: direct Joern CLI

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern-parse <source> -o <cpg.bin> --language java`.
2. `joern <cpg.bin> --script .opencode/shared/security-audit/joern-rules/java/java-deserialization-trace-callers.sc`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
