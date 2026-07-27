# Joern Rules

Store Joern and CPG-based static-analysis rules here.

Recommended layout:

- `index.json`: inventory of rules.
- `<language>/<rule-id>.sc`: Joern query or script for direct `joern <cpg.bin> --script <rule.sc>` execution; the CLI preloads the CPG, so rules do not use `importCpg` / `@main`.
- `<language>/<rule-id>.md`: rule intent, source/sink model, expected hits, known false positives, and test notes.

Rules should support defensive static analysis only.

## Java seed

105 rules promoted from `vuln_skill_builder` deep packs into `java/`, adapted for direct CLI execution:

```sh
joern-parse <source> -o <cpg.bin> --language java >parse.stdout.log 2>parse.stderr.log
joern <cpg.bin> --script .opencode/shared/security-audit/joern-rules/java/<rule-id>.sc >rule.stdout.log 2>rule.stderr.log
```

Keep full logs outside the agent context and return only a bounded summary.
