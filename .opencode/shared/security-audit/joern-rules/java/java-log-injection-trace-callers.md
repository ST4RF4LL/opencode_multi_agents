# java-log-injection-trace-callers

- **language**: java
- **skill**: `java-log-injection`
- **weakness**: `log-injection`
- **dimension**: D8
- **source_script**: `skills/java-subagent/java-log-injection/rules/joern/trace-callers.sc`
- **execution**: direct Joern CLI
- **params**: []

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern-parse <source> -o <cpg.bin> --language java`.
2. `joern <cpg.bin> --script .opencode/shared/security-audit/joern-rules/java/java-log-injection-trace-callers.sc`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
