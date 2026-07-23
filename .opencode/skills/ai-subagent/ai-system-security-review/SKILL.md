---
name: ai-system-security-review
description: Audit AI, LLM, agentic, RAG, vector, memory, MCP/tool, model-provider, training, evaluation, and model-artifact security as a full-repository Tri-Lens overlay. Use when reviewing any repository for AI-specific attack paths, including projects where AI applicability must be proven absent rather than assumed.
---

# AI System Security Review

Review the entire frozen file and function scope a second time for AI-specific risk. Do not limit discovery to filenames containing `ai`, `llm`, `prompt`, `rag`, or `model`; wrappers, generic HTTP clients, policy code, build files, and browser handlers can form AI attack paths.

## Required Inputs

Require all of the following before closing coverage:

- the frozen scope manifest and every complete AST/CPG function manifest
- `ai-surfaces.json` from Recon, including empty-but-explained inventories
- the unified application/AI vulnerability catalog and every `applies_to: ["ai"]` item
- exact file, function, and AI catalog assignments for one lens
- entry-point, sink, sensitive-operation, and config-surface inventories
- `audit_id`, `round`, `agent_session_id`, scope digest, and depth

An incomplete function inventory, missing scope digest, or missing AI inventory is a `GAP`. Grep results are discovery evidence, not a substitute for deterministic scope.

Read [references/owasp-ai-agent-security-checklist.md](references/owasp-ai-agent-security-checklist.md) whenever agents, tools, persistent memory, inter-agent communication, AI-assisted configuration, or high-impact actions are present. Apply its acceptance criteria through the assigned lens.

## Build the AI Surface Model

Map evidence for:

- model providers, endpoints, gateways, local runtimes, model IDs, fallbacks, and safety settings
- system/developer/user prompts, templates, multimodal inputs, context assembly, and output parsers
- agents, planners, routers, tools, plugins, MCP servers/clients, browser/computer use, and delegated credentials
- action-risk classification, previews, parameter-bound approvals, step-up authentication, replay/idempotency controls, interruption, and rollback
- agent registries, trust levels, signed or integrity-protected messages, recipient/type allowlists, freshness checks, shared state, and circuit breakers
- RAG ingestion, chunking, embeddings, vector stores, retrieval filters, rerankers, citations, and tenant boundaries
- short/long-term memory, caches, checkpoints, conversation stores, and cross-session state
- training/fine-tuning data, labeling, model artifacts, serialization/load paths, registries, and provenance
- evaluation suites, abuse-case regressions, CI/CD security gates, guardrails, observability, cost/token limits, rollout, drift, and rollback
- AI developer consoles or configuration assistants that consume repository, issue, document, web, or API content and can alter prompts, tools, policies, models, or safety settings

For each surface, record producers, consumers, trust boundary, attacker influence, identity/tenant, data classification, control owner, deployment uncertainty, and related files/functions.

## Execute One Lens

Apply exactly one assigned strategy across every D1-D10 dimension, every assigned file, every assigned function, and every AI catalog item:

- `sink-driven`: start at model invocations, output interpreters, tool execution, high-impact actions, approval consumption, MCP and inter-agent receivers, AI console mutations, retrieval and memory writes/reads, model loaders, outbound data, logs, and cost-amplifying loops; trace influence backward through prompt/context/data construction.
- `control-driven`: enumerate AI identities, sessions, agents, tools, knowledge bases, model/data lifecycle operations, approvals, tenant boundaries, trust transitions, and state changes; verify independent authorization, parameter-bound approval, least privilege, message integrity, isolation, provenance, rollback, validation, monitoring, and fail-closed behavior.
- `config-driven`: resolve effective provider/model/tool policies, prompt and guardrail versions, risk thresholds, approval TTL, replay/idempotency controls, output constraints, retrieval filters, memory TTL/isolation, agent trust registries, message freshness, circuit breakers, safety filters, credential scopes, network egress, token/cost/time limits, logging/redaction, test gates, artifact trust, and fallback precedence.

A control discovered under another lens may be reused as evidence, but it does not replace the current lens's analysis.

## Mandatory Risk Families

Iterate the AI catalog without sampling. At minimum consider direct, indirect, and multimodal prompt injection; unsafe output handling and exfiltration; excessive agency; goal hijacking; high-impact action and approval manipulation; confused deputy and delegated authorization; tool/MCP/plugin poisoning; multi-agent cascading failure; memory and context poisoning; RAG/vector authorization and poisoning; sensitive-data and system-prompt disclosure; AI console configuration manipulation; model/data/provider supply chain; training/backdoor/evaluation contamination; unsafe model artifact loading; model extraction/inversion; jailbreak and adversarial evasion; misinformation and unsafe overreliance; denial of wallet; observability failures; missing adversarial regression gates; insecure configuration; and lifecycle drift/rollback failures.

Do not report a model behavior in isolation. Tie candidates to an application asset, reachable trust boundary, missing or bypassable control, and consequence.

## Evidence and Accounting

- Preserve the pre-initialized arrays; close each `domain=ai` file/function/catalog row in place.
- Use `REVIEWED`, `FINDING`, or `GAP` for entity records. An empty AI inventory does not justify a skipped overlay; record absence as `REVIEWED` with bound evidence. Only the coverage reconciler may emit a zero-target `N/A` dimension cell.
- `N/A` for a file or function requires inspected-code evidence showing no AI data/control/tool/model role. Project-wide AI absence requires full-scope records plus negative dependency/config/runtime-interface evidence.
- Cite concrete file/line, symbol, configuration precedence, manifest ID, or tool result. Distinguish repository evidence from deployed/runtime assumptions.
- Redact prompts, credentials, personal data, model inputs/outputs, and retrieved documents when they contain secrets or sensitive content.
- Keep dynamic provider behavior, hosted guardrails, remote MCP capabilities, runtime prompt construction, and deployed model versions as explicit gaps unless authorized evidence establishes them.

Static review may use local parsers and analyzers. Do not send repository data to external models or providers, execute untrusted model artifacts, attack third-party services, or run live jailbreak/tool actions; route those requests to the validator under explicit authorization.

## Output

Write `reports/vulnerability-mining/ai-security-auditor.<agent_session_id>.audit-report.json`. It must contain one lens, all D1-D10 cells, the frozen digest, exact full-scope `domain=ai` file/function records, all AI catalog records, findings, artifacts, learning candidates, and references to `ai-surfaces.json`.
