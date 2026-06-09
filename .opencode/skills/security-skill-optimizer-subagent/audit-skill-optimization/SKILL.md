---
name: audit-skill-optimization
description: Improve security audit SKILL.md files from validation feedback without bloating prompts or changing agent role boundaries.
license: MIT
compatibility: opencode
metadata:
  role: security-skill-optimizer
  phase: feedback-loop
---

# Audit Skill Optimization

Use this skill when validation results show that an audit skill should be updated.

## Update Rules

- Add guidance only when it changes future reviewer behavior.
- Put language-specific guidance in the language-specific skill, not in the common skill, unless it applies across languages.
- Convert repeated false positives into guard-condition checks.
- Convert confirmed misses into source/sink patterns, reachability checks, or evidence requirements.
- Keep examples short and defensive. Avoid exploit chains beyond local validation context.

## Quality Bar

Each `SKILL.md` change should answer:

- What pattern should future audits recognize?
- What evidence confirms or rejects the issue?
- Which language, framework, or weakness class owns the guidance?
- What would be overfitting to this single repository?
