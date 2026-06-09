# C/C++ Subagent Skill Collection

This directory is the skill collection for `c-cpp-source-auditor`, not a single OpenCode skill.

OpenCode-discoverable skills are listed in `collection.json` and live under `.opencode/skills/c-cpp-subagent/<skill-name>/SKILL.md`.

To add a C/C++ audit skill:

1. Create `.opencode/skills/c-cpp-subagent/<skill-name>/SKILL.md`.
2. Use a permitted prefix such as `c-cpp-*`, `cpp-*`, `native-security-*`, or `memory-safety-*`.
3. Add the skill name to this collection's `collection.json`.
4. Update `.opencode/agent-manifest/skill-map.json` if the collection-to-agent mapping needs adjustment.
