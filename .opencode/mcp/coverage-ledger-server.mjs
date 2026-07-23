#!/usr/bin/env node

import { McpServer } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js";
import { StdioServerTransport } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js";
import { z } from "../node_modules/zod/index.js";
import { resolve } from "node:path";
import {
  canonicalCoveragePaths,
  finalizeLedger,
  getGaps,
  getPackets,
  inspectSubject,
  recordToolResult,
  submitDecision,
} from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-ledger-core.mjs";

const WORKSPACE_ROOT = resolve(process.cwd());
let mutationQueue = Promise.resolve();

function paths(auditId) {
  return canonicalCoveragePaths(WORKSPACE_ROOT, auditId);
}

function textResult(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

function serialized(operation) {
  const queued = mutationQueue.then(operation, operation);
  mutationQueue = queued.then(() => undefined, () => undefined);
  return queued;
}

const sourceHashSchema = z.object({
  file_id: z.string(),
  sha256: z.string().nullable(),
  link_target: z.string().nullable().optional(),
});
const locatorSchema = z.object({}).passthrough();

const server = new McpServer({
  name: "coverage_ledger",
  version: "2.0.0",
}, {
  capabilities: { tools: {} },
});

server.registerTool("coverage_get_packet", {
  description: "Return unresolved REQUIRED atomic coverage checks from the frozen Coverage Plan. This also initializes the canonical append-only ledger when needed.",
  inputSchema: {
    audit_id: z.string(),
    focus_area_id: z.string().optional(),
    domain: z.string().optional(),
    lens: z.enum(["sink-driven", "control-driven", "config-driven"]).optional(),
    subject_kind: z.enum(["catalog-domain", "interface"]).optional(),
    limit: z.number().int().min(1).max(250).optional(),
  },
}, async ({ audit_id, focus_area_id, domain, lens, subject_kind, limit }) => {
  const { planPath, ledgerPath } = paths(audit_id);
  return textResult(await serialized(() => getPackets({
    planPath,
    ledgerPath,
    focusAreaId: focus_area_id,
    domain,
    lens,
    subjectKind: subject_kind,
    limit,
  })));
});

server.registerTool("coverage_inspect_subject", {
  description: "Record that a session inspected one REQUIRED check and return its immutable packet. N/A decisions cannot be submitted through this service.",
  inputSchema: {
    audit_id: z.string(),
    check_id: z.string(),
    session_id: z.string(),
    idempotency_key: z.string(),
  },
}, async ({ audit_id, check_id, session_id, idempotency_key }) => {
  const { planPath, ledgerPath } = paths(audit_id);
  return textResult(await serialized(() => inspectSubject({
    planPath,
    ledgerPath,
    checkId: check_id,
    sessionId: session_id,
    idempotencyKey: idempotency_key,
  })));
});

server.registerTool("coverage_record_tool_result", {
  description: "Create a digest-bound evidence receipt for one REQUIRED check. Source hashes must match the frozen plan; stale or invented sources are rejected.",
  inputSchema: {
    audit_id: z.string(),
    check_id: z.string(),
    session_id: z.string(),
    idempotency_key: z.string(),
    source_hashes: z.array(sourceHashSchema).min(1),
    locators: z.array(locatorSchema).min(1),
    query_or_rule: z.string(),
    tool: z.string(),
    result_digest: z.string(),
    result_summary: z.string().optional(),
  },
}, async input => {
  const { planPath, ledgerPath } = paths(input.audit_id);
  return textResult(await serialized(() => recordToolResult({
    planPath,
    ledgerPath,
    checkId: input.check_id,
    sessionId: input.session_id,
    idempotencyKey: input.idempotency_key,
    sourceHashes: input.source_hashes,
    locators: input.locators,
    queryOrRule: input.query_or_rule,
    tool: input.tool,
    resultDigest: input.result_digest,
    resultSummary: input.result_summary,
  })));
});

server.registerTool("coverage_submit_decision", {
  description: "Submit VERIFIED, GAP, or INVALIDATED plus an independent result state. VERIFIED requires a receipt generated for the same check. Planner-only N/A is rejected.",
  inputSchema: {
    audit_id: z.string(),
    check_id: z.string(),
    session_id: z.string(),
    idempotency_key: z.string(),
    execution_state: z.enum(["VERIFIED", "GAP", "INVALIDATED"]),
    result_state: z.enum(["NO_FINDING", "FINDING", "INCONCLUSIVE"]),
    receipt_ids: z.array(z.string()).optional(),
    finding_ids: z.array(z.string()).optional(),
    rationale: z.string(),
  },
}, async input => {
  const { planPath, ledgerPath } = paths(input.audit_id);
  return textResult(await serialized(() => submitDecision({
    planPath,
    ledgerPath,
    checkId: input.check_id,
    sessionId: input.session_id,
    idempotencyKey: input.idempotency_key,
    executionState: input.execution_state,
    resultState: input.result_state,
    receiptIds: input.receipt_ids ?? [],
    findingIds: input.finding_ids ?? [],
    rationale: input.rationale,
  })));
});

server.registerTool("coverage_get_gaps", {
  description: "Return every REQUIRED check whose latest execution state is not VERIFIED, including PLANNED, INSPECTED, GAP, and INVALIDATED.",
  inputSchema: { audit_id: z.string() },
}, async ({ audit_id }) => {
  const { planPath, ledgerPath } = paths(audit_id);
  return textResult(await serialized(() => getGaps({ planPath, ledgerPath })));
});

server.registerTool("coverage_finalize", {
  description: "Finalize and seal the ledger only when the frozen plan has no UNKNOWN applicability and every REQUIRED check is VERIFIED.",
  inputSchema: {
    audit_id: z.string(),
    idempotency_key: z.string(),
  },
}, async ({ audit_id, idempotency_key }) => {
  const { planPath, ledgerPath } = paths(audit_id);
  return textResult(await serialized(() => finalizeLedger({
    planPath,
    ledgerPath,
    idempotencyKey: idempotency_key,
  })));
});

const transport = new StdioServerTransport();
await server.connect(transport);
