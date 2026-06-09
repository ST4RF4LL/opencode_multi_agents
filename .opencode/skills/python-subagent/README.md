# Python Subagent Skill Collection

This directory is the skill collection for `python-source-auditor`, not a single OpenCode skill.

OpenCode-discoverable skills are listed in `collection.json` and live under `.opencode/skills/python-subagent/<skill-name>/SKILL.md`.

To add a Python audit skill:

1. Create `.opencode/skills/python-subagent/<skill-name>/SKILL.md`.
2. Use a permitted prefix such as `python-*`, `py-*`, `django-security-*`, `flask-security-*`, or `fastapi-security-*`.
3. Add the skill name to this collection's `collection.json`.
4. Add it to `.opencode/agent-manifest/skill-map.json` if it should be required rather than optional.
