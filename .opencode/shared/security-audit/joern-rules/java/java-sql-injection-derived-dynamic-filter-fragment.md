# java-sql-injection-derived-dynamic-filter-fragment

- **language**: java
- **skill**: `java-sql-injection`
- **weakness**: `sql-injection`
- **dimension**: D1
- **source_script**: `skills/java-subagent/java-sql-injection/rules/joern/derived/dynamic-filter-fragment.sc`
- **execution**: direct Joern CLI
- **params**: ['cpgFile: String']

## Intent

Static Joern query published for `java-source-auditor` / `security-skill-optimizer`.
Outputs candidates (sinks/sources/flows/validation hints), not final findings.

## How to run

1. `joern-parse <source> -o <cpg.bin> --language java`.
2. `joern <cpg.bin> --script .opencode/shared/security-audit/joern-rules/java/java-sql-injection-derived-dynamic-filter-fragment.sc`.

## Safety

Defensive static analysis only. Do not encode exploit payload delivery.
