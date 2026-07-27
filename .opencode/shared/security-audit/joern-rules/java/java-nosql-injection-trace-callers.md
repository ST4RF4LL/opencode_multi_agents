# java-nosql-injection-trace-callers

- **language**: java
- **skill**: `java-nosql-injection`
- **weakness**: `nosql-injection`
- **dimension**: D1
- **source_script**: `skills/java-subagent/java-nosql-injection/rules/joern/trace-callers.sc`
- **execution**: direct Joern CLI
- **params**: ['cpgFile: String', 'sinkMethod: String = ".*Document\\\\.parse.*"']

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern-parse <source> -o <cpg.bin> --language java`.
2. `joern <cpg.bin> --script .opencode/shared/security-audit/joern-rules/java/java-nosql-injection-trace-callers.sc`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
