---
name: c-cpp-memory-safety-review
description: Review C/C++ code for memory safety issues including bounds errors, use-after-free, double free, and lifetime mistakes.
license: MIT
compatibility: opencode
metadata:
  role: c-cpp-source-auditor
  collection: c-cpp-subagent
---

# C/C++ Memory Safety Review

Use this skill when reviewing native code that handles buffers, pointers, allocation, parsing, or object lifetimes.

## Focus Areas

- Out-of-bounds read/write from unchecked indexes, lengths, pointer arithmetic, or sentinel assumptions.
- Use-after-free, double free, invalid free, allocator mismatch, and borrowed pointer lifetime bugs.
- Stack and heap overflows from fixed-size buffers, unchecked copy operations, or unterminated strings.
- Integer overflow, signedness conversion, truncation, and allocation-size mismatch before copy or parse operations.
- Null pointer dereference only when it has a denial-of-service or control-flow security impact.

## Evidence Requirements

Identify the controlled input, allocation or buffer size, guard conditions, unsafe operation, and concrete failure mode.
