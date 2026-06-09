---
name: secure-code-review-common
description: Common secure code review workflow for source, sink, trust-boundary, reachability, and evidence-based vulnerability findings.
license: MIT
compatibility: opencode
metadata:
  role: source-auditor
  phase: source-review
---

# Secure Code Review Common

Use this skill as the shared review method for all language-specific auditors.

## Review Method

1. Map sources: external request parameters, headers, cookies, bodies, files, archives, environment variables, CLI args, queue messages, database content, and third-party callbacks.
2. Map sinks: SQL, shell/process execution, file paths, network fetches, templates, deserializers, crypto APIs, logging, redirects, authorization decisions, memory operations, and privileged actions.
3. Trace data flow between source and sink. Note sanitizers, validators, encoders, allowlists, auth checks, and type conversions.
4. Check reachability. Prefer findings that can be triggered through a real entrypoint.
5. Separate confirmed source-backed issues from weak patterns that need validation.

## Evidence Rules

- Every candidate finding needs an affected file and the relevant code path.
- Include why existing guards are insufficient.
- State confidence and what would change the conclusion.
- Do not invent runtime facts that are not visible in source, config, or user-provided context.

## Finding Minimum

Include weakness class, affected code, trigger/data flow, impact, validation need, and recommended fix.
