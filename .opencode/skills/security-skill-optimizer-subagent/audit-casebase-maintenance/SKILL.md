---
name: audit-casebase-maintenance
description: Maintain dimension-and-lens-tagged vulnerability and false-positive cases used to improve future Tri-Lens source and platform security audits.
license: MIT
metadata:
  role: security-skill-optimizer
  phase: casebase-maintenance
---

# Audit Casebase Maintenance

Use this skill when validation results should become reusable audit knowledge.

## Vulnerability Cases

Add a confirmed or likely case when it captures a reusable pattern:

- Language and framework.
- Dimension and originating lens.
- Weakness class.
- Sink, control, config, mitigating, and guard evidence facets that apply.
- Why validation confirmed or nearly confirmed it.
- What future audits should check.
- Fix guidance and how to validate the fix.

## False-Positive Cases

Add a false-positive case when it prevents recurring noise:

- Original suspicion.
- Dimension and originating lens.
- Rejecting evidence.
- Guard, sanitizer, framework behavior, or unreachable condition.
- Rule or skill refinement needed.
- Cases where the issue would become real.

## Storage

Store cases under `.opencode/shared/security-audit/vulnerability-cases/` and `.opencode/shared/security-audit/false-positive-cases/`. Keep case files small and searchable.
