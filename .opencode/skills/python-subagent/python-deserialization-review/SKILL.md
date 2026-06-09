---
name: python-deserialization-review
description: Review Python deserialization code for pickle, marshal, YAML, dill, joblib, and unsafe object construction risks.
license: MIT
compatibility: opencode
metadata:
  role: python-source-auditor
  collection: python-subagent
---

# Python Deserialization Review

Use this skill when Python code reads structured data from users, files, queues, caches, or admin import paths.

## Focus Areas

- `pickle`, `marshal`, `dill`, `joblib`, `shelve`, and framework helpers that deserialize Python objects.
- Unsafe `yaml.load`, custom constructors, object hooks, and dynamic class resolution.
- Deserialization of files, archives, session data, cache entries, queues, signed blobs, and admin uploads.
- Trust assumptions around signatures, encryption, file provenance, and internal-only endpoints.

## Evidence Requirements

Identify the input source, deserializer, type control, trust boundary, and whether integrity checks actually protect the payload.
