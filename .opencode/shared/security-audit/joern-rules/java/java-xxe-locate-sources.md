# java-xxe-locate-sources

- **language**: java
- **skill**: `java-xxe`
- **weakness**: `xxe`
- **dimension**: D1
- **source_script**: `skills/java-subagent/java-xxe/rules/joern/locate-sources.sc`
- **execution**: direct Joern CLI

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern-parse <source> -o <cpg.bin> --language java`.
2. `joern <cpg.bin> --script .opencode/shared/security-audit/joern-rules/java/java-xxe-locate-sources.sc`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
