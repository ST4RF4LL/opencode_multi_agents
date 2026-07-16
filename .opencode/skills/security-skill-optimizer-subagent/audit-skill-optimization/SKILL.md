---
name: audit-skill-optimization
description: Improve threat-led Focus Area Tri-Lens security audit skills from validation feedback, tagged by threat, Focus Area, dimension, lens, and discovery track without bloating prompts or changing agent role boundaries.
license: MIT
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
- Tag every change with `threat_id`, `focus_area_id`, `dimension`, `lens`, and `discovery_track` when known; use `cross-lens` only for correlation behavior.
- Put anchor discovery in Sink guidance, absent/present safeguards in Control guidance, and effective-setting/baseline logic in Config guidance.
- Keep examples short and defensive. Avoid exploit chains beyond local validation context.

## Quality Bar

Each `SKILL.md` change should answer:

- What pattern should future audits recognize?
- What evidence confirms or rejects the issue?
- Which language, framework, or weakness class owns the guidance?
- Which D1-D10 dimension and lens owns the guidance?
- Which threat class, Focus Area type, and discovery track produced or missed it?
- What would be overfitting to this single repository?
