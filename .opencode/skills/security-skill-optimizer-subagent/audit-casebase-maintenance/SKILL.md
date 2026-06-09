---
name: audit-casebase-maintenance
description: Maintain confirmed vulnerability cases and false-positive cases used to improve future source security audits.
license: MIT
compatibility: opencode
metadata:
  role: security-skill-optimizer
  phase: casebase-maintenance
---

# Audit Casebase Maintenance

Use this skill when validation results should become reusable audit knowledge.

## Vulnerability Cases

Add a confirmed or likely case when it captures a reusable pattern:

- Language and framework.
- Weakness class.
- Source, sink, and guard conditions.
- Why validation confirmed or nearly confirmed it.
- What future audits should check.
- Fix guidance and how to validate the fix.

## False-Positive Cases

Add a false-positive case when it prevents recurring noise:

- Original suspicion.
- Rejecting evidence.
- Guard, sanitizer, framework behavior, or unreachable condition.
- Rule or skill refinement needed.
- Cases where the issue would become real.

## Storage

Store cases under `.opencode/shared/security-audit/vulnerability-cases/` and `.opencode/shared/security-audit/false-positive-cases/`. Keep case files small and searchable.
