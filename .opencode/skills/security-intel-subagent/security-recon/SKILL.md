---
name: security-recon
description: Evidence-backed reconnaissance for Tri-Lens security audits. Use to build the attack-surface map plus entry-point, sink, sensitive-operation, config-surface, and AI-surface inventories before source, platform, or AI overlay auditors run.
license: MIT
metadata:
  role: security-intel-collector
  collection: security-intel-subagent
---

# Security Reconnaissance

Build normalized discovery inputs for all three audit lenses. Discover broadly but distinguish confirmed evidence, candidates, unknowns, and gaps.

## Workflow

1. Build the scope manifest once with `audit-coverage-accounting`; default to tracked plus untracked non-ignored Git content and use its recorded exclusions as the scope boundary. Use full filesystem mode only when ignored artifacts are explicitly in scope.
2. Build complete AST/CPG function manifests once with the bounded parallel driver. Joern must parse only its language-scoped source projection, and digest-bound results may be reused on resume. Do not use regex as a function universe.
3. Derive the five-layer attack surface: architecture, business, framework/language, deployment, and functions.
4. Build all five inventories below, including an empty-but-explained AI surface inventory when no AI use is found.
5. Map inventory items to D1-D10 without assigning exclusive lens ownership.
6. Emit the compact threat-routing index, and record discovery queries, inspected files, unsupported areas, builder timing/cache state, and secrets redaction.

## Entry-Point Inventory

Search framework-appropriate sources for:

- HTTP routes and controllers.
- RPC/GraphQL handlers.
- CLI commands and environment/config inputs.
- Message/event consumers and scheduled jobs.
- Upload/import/parsing handlers.
- Webhooks, callbacks, redirects, and plugin interfaces.

Record exposure, auth context, attacker-controlled fields, trust boundaries, and downstream component.

## Sink Inventory

Include anchors beyond classic injection sinks:

- SQL/NoSQL, command, expression, template, LDAP/XPath, response and log outputs.
- Deserialization/parsing, file read/write/upload/extract/execute, network clients and redirects.
- Token/password/session, crypto/key/TLS, and secret-consuming operations.
- State-changing, financial, approval, export, batch, and tenant-sensitive operations.
- Dependency/plugin APIs and build/CI execution steps.

Record category, location, candidate entry points, visible guards, and reachability confidence.

## Sensitive-Operation Inventory

Inventory operations requiring security controls, including cases where missing code cannot be found by grep:

- Authentication lifecycle: login, refresh, logout, recovery, enrollment, MFA.
- Resource CRUD grouped by resource type.
- Role/admin/tenant operations and ownership-sensitive access.
- Payment, balance, stock, coupon, approval, state transition, export, and batch actions.
- Key/secret management, deployments, releases, artifact publication, and dependency changes.

Record expected control classes and observed local, middleware, inherited, gateway, or platform controls.

## Config-Surface Inventory

Inspect precedence-aware configuration surfaces:

- Application settings and environment overrides.
- Authentication, authorization, parser, ORM, template, crypto, TLS, CORS, logging, and error settings.
- Dependency manifests, lockfiles, plugins, repositories, vendored code, and submodules.
- Build scripts, Docker/Compose, Kubernetes/Helm, CI/CD, proxies/gateways, service mesh, and IaC.

Record observed values only when safe, the likely effective precedence, consuming component, baseline target, and uncertainty. Redact secrets.

## AI-Surface Inventory

Search the complete scope, dependencies, configuration, network clients, data stores, build artifacts, and runtime interfaces for:

- hosted and local model providers, endpoints, gateways, model IDs, fallbacks, and credentials
- system/developer/user prompts, templates, context builders, multimodal inputs, output parsers, guardrails, and moderation
- agents, planners, routers, tools, plugins, MCP servers/clients, inter-agent protocols, delegated identities, and approval paths
- RAG ingestion, chunking, embeddings, vector stores, retrieval/reranking, document connectors, citations, and tenant filters
- memory, conversation stores, checkpoints, summaries, caches, long-term profiles, and cross-session state
- action-risk maps, previews, approval stores/tokens, step-up flows, execution-policy services, replay/idempotency controls, interrupt and rollback paths
- agent registries, trust levels, inter-agent transports and message types, signing/freshness checks, shared state, delegation chains, and circuit breakers
- training/fine-tuning datasets and jobs, model/adaptor/tokenizer artifacts, loaders, registries, evaluation suites, and promotion gates
- adversarial abuse-case suites, regression fixtures, CI/CD gates, validation evidence, token/cost/time limits, tracing and redaction, abuse monitoring, versioning, rollout, drift, rollback, and retirement
- AI consoles and configuration assistants that consume untrusted repository, issue, document, web, email, or API content before changing prompts, tools, models, policies, or safety settings

For each item record `kind`, provider or implementation, location, related file/function IDs, producer and consumer, attacker influence, trust boundary, identity and tenant context, data classification, configured controls, deployment uncertainty, and confidence.

If no item is found, do not omit the file. Record the dependency/config/API and full-scope searches used as negative evidence, keep any runtime uncertainty in `gaps`, and leave final AI applicability to the full-scope AI auditor.

## Applicability Matrix

For D1-D10, use only `applicable`, `not-applicable`, or `unknown` and attach evidence. `not-applicable` requires both functional absence and scoped search evidence. Do not convert applicability into audit completion.

## Inventory Schema

Each JSON file must contain:

```json
{
  "schema_version": 1,
  "audit_id": "audit-id",
  "scope": ["path"],
  "items": [
    {
      "id": "stable-id",
      "kind": "entry|sink|operation|config|ai-surface",
      "language": "java|web|python|c-cpp|platform|ai",
      "location": "file:line",
      "dimensions": ["D1"],
      "evidence": "what was observed",
      "discovery_method": "query or inspection",
      "confidence": "confirmed|candidate|unknown"
    }
  ],
  "gaps": [],
  "tool_inputs": []
}
```

Write the five inventory files—`entry-points.json`, `sinks.json`, `sensitive-operations.json`, `config-surfaces.json`, and `ai-surfaces.json`—plus `recon-summary.json` beneath `tmp/<audit_id>/recon/`. Every file must include `audit_id`, `scope_digest`, `items`, `gaps`, and discovery inputs.

Write `scope-manifest.json`, all function manifests, and `threat-routing-index.json` beneath `tmp/<audit_id>/recon/coverage/`. Bind every inventory and routing record to the same `scope_digest`. Later phases consume the compact routing index and must not rerun builders.

## Completion Checklist

- [ ] Five-layer attack surface contains evidence and trust boundaries.
- [ ] Recursive scope has no unreadable/unassigned item and records every exclusion.
- [ ] Every function-bearing file occurs in exactly one complete AST/CPG manifest.
- [ ] Language/platform routing covers every in-scope artifact type.
- [ ] All five inventories exist, including an evidence-backed AI inventory or explicit negative evidence.
- [ ] CRUD and business operations are grouped for consistency checks.
- [ ] Configuration precedence and environment uncertainty are recorded.
- [ ] D1-D10 applicability has evidence.
- [ ] Discovery gaps and unsupported languages/tools are explicit.
