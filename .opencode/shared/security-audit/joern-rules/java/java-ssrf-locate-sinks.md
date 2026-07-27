# java-ssrf-locate-sinks

- **language**: java
- **skill**: `java-ssrf`
- **weakness**: `ssrf`
- **dimension**: D6
- **source_script**: `skills/java-subagent/java-ssrf/rules/joern/locate-sinks.sc`
- **execution**: direct Joern CLI

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern-parse <source> -o <cpg.bin> --language java`.
2. `joern <cpg.bin> --script .opencode/shared/security-audit/joern-rules/java/java-ssrf-locate-sinks.sc`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
