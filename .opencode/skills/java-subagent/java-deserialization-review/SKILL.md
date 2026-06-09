---
name: java-deserialization-review
description: Review Java/JVM deserialization and object-mapping code for gadget, polymorphic typing, and unsafe type resolution risks.
license: MIT
compatibility: opencode
metadata:
  role: java-source-auditor
  collection: java-subagent
---

# Java Deserialization Review

Use this skill for Java serialization, object mappers, and message formats that can instantiate attacker-influenced types.

## Focus Areas

- Native Java serialization, `readObject`, `ObjectInputStream`, RMI, JMX, and custom class resolution.
- Jackson polymorphic typing, XStream, Kryo, Hessian, SnakeYAML, XML decoders, and custom converters.
- Gadget availability through dependencies and classpath exposure.
- Allowlist/denylist gaps, trusted package assumptions, and unsafe default typing.
- Deserialization reachable from HTTP, RPC, queues, cache entries, files, or admin import functions.

## Evidence Requirements

Identify the input format, deserializer, type controls, classpath assumptions, and reachability from an entrypoint.
