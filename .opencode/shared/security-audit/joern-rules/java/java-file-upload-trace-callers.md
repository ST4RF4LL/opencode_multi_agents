# java-file-upload-trace-callers

- **language**: java
- **skill**: `java-file-upload`
- **weakness**: `file-upload`
- **dimension**: D5
- **source_script**: `skills/java-subagent/java-file-upload/rules/joern/trace-callers.sc`
- **execution**: direct Joern CLI

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern-parse <source> -o <cpg.bin> --language java`.
2. `joern <cpg.bin> --script .opencode/shared/security-audit/joern-rules/java/java-file-upload-trace-callers.sc`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
