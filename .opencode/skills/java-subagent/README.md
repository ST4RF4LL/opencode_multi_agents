# Java Subagent Skill Collection

This directory is the skill collection for `java-source-auditor`, not a single OpenCode skill.

OpenCode-discoverable skills are listed in `collection.json` and live under `.opencode/skills/java-subagent/<skill-name>/SKILL.md`.

To add a Java/JVM audit skill:

1. Create `.opencode/skills/java-subagent/<skill-name>/SKILL.md`.
2. Use a permitted prefix such as `java-*`, `jvm-*`, `spring-security-*`, or `deserialization-*`.
3. Add the skill name to this collection's `collection.json`.
4. Update `.opencode/agent-manifest/skill-map.json` if the collection-to-agent mapping needs adjustment.
