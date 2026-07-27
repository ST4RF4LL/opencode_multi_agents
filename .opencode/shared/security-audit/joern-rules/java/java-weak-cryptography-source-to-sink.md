# java-weak-cryptography-source-to-sink

- **language**: java
- **skill**: `java-weak-cryptography`
- **weakness**: `weak-cryptography`
- **dimension**: D7
- **source_script**: `skills/java-subagent/java-weak-cryptography/rules/joern/source-to-sink.sc`
- **execution**: direct Joern CLI
- **params**: ['cpgFile: String']

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern-parse <source> -o <cpg.bin> --language java`.
2. `joern <cpg.bin> --script .opencode/shared/security-audit/joern-rules/java/java-weak-cryptography-source-to-sink.sc`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
