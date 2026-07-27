# java-jwt-misuse-trace-callers

- **language**: java
- **skill**: `java-jwt-misuse`
- **weakness**: `jwt-misuse`
- **dimension**: D2
- **source_script**: `skills/java-subagent/java-jwt-misuse/rules/joern/trace-callers.sc`
- **execution**: direct Joern CLI

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern-parse <source> -o <cpg.bin> --language java`.
2. `joern <cpg.bin> --script .opencode/shared/security-audit/joern-rules/java/java-jwt-misuse-trace-callers.sc`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
