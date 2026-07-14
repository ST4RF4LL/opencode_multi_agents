# Joern rules derived from real cases

These scripts are **pattern detectors**, not exploit payloads.

| Script | Source cases | Detects |
|--------|--------------|---------|
| `dynamic-identifier.sc` | CVE-2026-26198 ormar | column/sort/table identifier injection |
| `map-key-to-sql.sc` | CVE-2025-65896 asyncmy | map keys as SQL identifiers |
| `raw-sql-execution.sc` | CVE-2024-12909 llama-index | fully controlled SQL execution |
| `operator-connector-inject.sc` | H1 #3335709 Django Q | AND/OR/connector injection |
| `dynamic-filter-fragment.sc` | H1 #3292573 FilteredRelation | dynamic join/filter fragments |
| `path-param-to-sql.sc` | H1 #2958619 etc. | path variable → SQL |

Run example:

```bash
joern --script rules/joern/derived/dynamic-identifier.sc --param cpgFile=/path/to/cpg.bin
```

Always combine with Evidence Contract in `evidence/contract.yaml` before reporting a Finding.
