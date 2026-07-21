---
name: joern-rule-maintenance
description: Maintain dimension-and-lens-tagged Joern static-analysis rules and metadata from completed final-report-bound vuln-judger TRUE_POSITIVE and FALSE_POSITIVE results.
license: MIT
metadata:
  role: security-skill-optimizer
  phase: rule-maintenance
---

# Joern Rule Maintenance

Use this skill when validator feedback should change Joern or CPG-based static-analysis rules.

## Rule Lifecycle

- Add a rule when a `TRUE_POSITIVE` finding has a reusable source/sink, API, or data-flow shape.
- Refine a rule when completed three-party review exposes missing guards, sanitizers, framework semantics, or reachability checks.
- Deprecate or remove a rule when it is noisy and cannot be made precise enough for the target role.
- Record rule intent, language, dimension, originating lens, weakness class, expected evidence, known false positives, and test cases in metadata.

## Storage

Store rule assets under `.opencode/shared/security-audit/joern-rules/`.

Recommended layout:

- `index.json`: rule inventory.
- `<language>/<rule-id>.sc`: Joern query or script.
- `<language>/<rule-id>.md`: intent, source/sink model, expected hits, and false-positive notes.

## Safety

Rules must support authorized static analysis only. Do not encode exploit payload delivery or external attack behavior.
