# False-Positive Cases

Store reusable false-positive cases here.

Recommended fields:

- `id`
- `language`
- `original_suspicion`
- `rejecting_evidence`
- `guard_or_sanitizer`
- `rule_refinement`
- `skill_refinement`
- `when_it_would_be_real`

## Layout

- `index.json`: inventory.
- `<language>/<id>.md`: human-readable pattern notes.
- Optional `<language>/<id>.yaml`: machine-oriented pattern list (`not_vulnerability`, `needs_deeper_review`).

Java seed packs: `java/<skill>-fp.md` promoted from each deep skill's `analysis/false-positive-patterns.yaml`.
