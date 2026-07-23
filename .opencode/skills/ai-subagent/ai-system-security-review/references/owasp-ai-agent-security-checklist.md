# OWASP AI Agent Security Control Matrix

Use this matrix with the unified vulnerability catalog when the scoped system contains agents, tool use, persistent memory, multiple cooperating agents, or AI-assisted configuration.

Source baseline: [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).

## Risk Mapping

| Risk family | Required focus | Catalog mapping |
|---|---|---|
| Direct or indirect prompt injection | Treat user, document, web, email, API, retrieval, tool, and inter-agent content as untrusted data | `AI-PROMPT-01`, `AI-ROBUST-01` |
| Tool abuse and privilege escalation | Limit tools by task, trust level, operation, resource, identity, and tenant | `AI-TOOL-01`, `AI-AGENT-01`, `AI-IDENTITY-01` |
| Data exfiltration | Inspect model output, tool parameters, URLs, webhooks, logs, traces, citations, and inter-agent payloads | `AI-DATA-01`, `AI-OUTPUT-01` |
| Memory poisoning | Validate before write and recall; isolate, expire, bound, redact, and integrity-protect persistent state | `AI-MEMORY-01` |
| Goal hijacking | Prevent untrusted data from rewriting goals, plans, policies, risk scores, or configuration | `AI-PROMPT-01`, `AI-CONSOLE-01` |
| High-impact action or approval abuse | Independently authorize and bind approval to the exact operation | `AI-APPROVAL-01` |
| Multi-agent cascading failure | Authenticate, authorize, validate, isolate, and circuit-break inter-agent communication | `AI-MULTIAGENT-01` |
| AI console malicious configuration | Treat repository, issue, document, and remote content consumed by configuration assistants as untrusted | `AI-CONSOLE-01`, `AI-CONFIG-01` |
| Denial of wallet | Bound tokens, retries, recursion, fan-out, tools, time, compute, and provider spend | `AI-RESOURCE-01` |
| Sensitive data exposure | Classify and minimize context; redact logs and outputs; encrypt retained data | `AI-DATA-01`, `AI-PRIVACY-01` |
| Agent supply chain | Establish provenance and change controls for tools, APIs, MCP servers, providers, data, and models | `AI-SUPPLY-01`, `AI-TOOL-01` |
| Missing adversarial validation | Maintain abuse-case regressions and release gates for every material agent change | `AI-TEST-01`, `AI-LIFECYCLE-01` |

## Control Acceptance Criteria

### 1. Tool Security and Least Privilege

- Inventory every tool and its read/write/execute behavior, reachable resources, network destinations, credential, tenant context, and destructive effect.
- Require task-specific tool sets rather than wildcard access; separate low-trust or user-facing agents from privileged/internal agents.
- Enforce authorization in middleware or the execution component. A model request or prompt instruction is never authorization.
- Revalidate normalized parameters and resource scope immediately before execution.

### 2. Input and Prompt Boundaries

- Mark all external and cross-agent content untrusted regardless of apparent source or format.
- Canonicalize, size-bound, validate, and label content before context assembly.
- Keep instructions and data structurally separated and preserve provenance through summarization or retrieval.
- Treat model-based screening as an additional signal, not the sole enforcement boundary.

### 3. Memory and Context

- Validate and sanitize content both before persistence and before recall.
- Isolate memory by user, tenant, session, agent, purpose, and environment.
- Enforce TTL, item count, item size, deletion, and compaction rules.
- Redact or reject sensitive values and integrity-protect long-lived memory; detect stale or modified entries.

### 4. Human Oversight and High-Impact Actions

- Classify actions by impact and require explicit previews for destructive, financial, administrative, externally visible, or irreversible operations.
- Separate proposal from execution; an independent policy or execution service must validate identity, privilege, scope, and approval.
- Bind approval to actor, session, tool, target, normalized parameters, timestamp, expiry, and policy version.
- Use short-lived authorization, replay protection, step-up authentication, idempotency, duplicate confirmation, interruption, and rollback where applicable.
- Fail closed if risk classification, approval validation, policy lookup, or audit recording is unavailable.

### 5. Output Validation and Guardrails

- Validate structured outputs against strict schemas and allowlists before display or execution.
- Apply context-specific encoding, sensitive-data filtering, destination restrictions, and action-rate or scope limits.
- Detect exfiltration through URLs, webhooks, encoded fields, large payloads, citations, tool parameters, logs, and final responses.
- Reauthorize consequential actions after output validation.

### 6. Monitoring and Observability

- Record agent/session/user identity, decision, tool, normalized target, policy and model/prompt versions, authorization result, approval ID, outcome, latency, token use, and cost.
- Redact sensitive values before persistence and protect audit integrity and access.
- Detect unusual tool frequency, repeated failures or approval bypasses, privilege elevation, sensitive-data access, recursion, spend, and drift in approval behavior.
- Retain enough evidence to reconstruct decisions, denials, timeouts, rollbacks, and circuit-breaker events.

### 7. Multi-Agent Security

- Maintain an authenticated agent registry with explicit trust levels, allowed recipients, message types, tools, and delegation limits.
- Sign messages or otherwise provide integrity and sender authentication; verify recipient, freshness, and replay protection.
- Validate and sanitize payloads at every handoff. Do not inherit the sender's privilege or trust claims.
- Isolate execution and shared state, cap chain depth, and use circuit breakers to contain a compromised or failing agent.

### 8. Data Protection and Privacy

- Classify data at least as public, internal, confidential, or restricted and define handling by operation: context, tool, memory, log, trace, output, and export.
- Minimize data before context construction and enforce tenant, purpose, consent, retention, and deletion rules.
- Encrypt sensitive data in transit and at rest and prevent plaintext credentials or personal data in memory and telemetry.

### 9. Security Testing and Release Gates

- Maintain repeatable tests for prompt override, unauthorized tool requests, privilege escalation, memory poisoning, data exfiltration, recursive tool abuse, approval bypass, and multi-agent chaining.
- Run tests before production and after material changes to prompts, tools, memory, retrieval, policies, models, or providers.
- Gate releases on expected denials, limits, approvals, timeouts, and circuit breakers; preserve regressions for previous failures.
- Protect security tests from being weakened in the same change and keep fixtures free of secrets or live customer data.
- Bind validation evidence to agent version, model/provider, prompt, tool policy, retrieval configuration, expected result, observed result, and accepted residual risk.

## Tri-Lens Routing

- `sink-driven`: start from tool execution, high-impact actions, approval consumption, outbound data paths, memory writes/reads, inter-agent receivers, AI console mutations, and resource-amplifying loops.
- `control-driven`: verify independent authorization, approval binding, trust transitions, message integrity, memory isolation, data classification, interruption/rollback, and release gates.
- `config-driven`: resolve tool allowlists, trust levels, risk thresholds, approval TTL, replay and idempotency settings, memory limits, message freshness, circuit breakers, observability thresholds, budgets, and CI gate precedence.

Use `GAP` when runtime evidence is necessary to establish provider behavior, real approval enforcement, remote tool capabilities, deployed trust registries, or execution isolation.
