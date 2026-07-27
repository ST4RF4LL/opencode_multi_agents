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
  getSubjectSources,
  inspectSubject,
  recordToolResult,
  submitDecision,
} from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-ledger-core.mjs";

const WORKSPACE_ROOT = resolve(process.cwd());
const MAX_RESPONSE_BYTES = 16 * 1024;
const MAX_BATCH_ITEMS = 100;
const MAX_LOCATORS_BYTES = 16 * 1024;
const MAX_ID_LIST_BYTES = 16 * 1024;
let mutationQueue = Promise.resolve();

function paths(auditId) {
  return canonicalCoveragePaths(WORKSPACE_ROOT, auditId);
}

function textResult(value) {
  const text = JSON.stringify(value);
  if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) {
    throw new Error(`Coverage response exceeds the ${MAX_RESPONSE_BYTES}-byte safety limit; request a smaller page or a single subject`);
  }
  return { content: [{ type: "text", text }] };
}

function serialized(operation) {
  const queued = mutationQueue.then(operation, operation);
  mutationQueue = queued.then(() => undefined, () => undefined);
  return queued;
}

const sourceHashSchema = z.object({
  file_id: z.string().max(255),
  sha256: z.string().max(128).nullable(),
  link_target: z.string().max(4096).nullable().optional(),
});
const locatorSchema = z.object({}).passthrough();
const auditIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._-]{2,127}$/i, "Invalid audit_id");
const checkIdSchema = z.string().min(1).max(255);
const sessionIdSchema = z.string().min(3).max(255);
const idempotencyKeySchema = z.string().min(1).max(255);
const cursorSchema = z.string().max(64);

function assertJsonSize(value, label, maxBytes) {
  if (Buffer.byteLength(JSON.stringify(value), "utf8") > maxBytes) {
    throw new Error(`${label} exceeds the ${maxBytes}-byte input limit; split it into smaller receipts`);
  }
}

function compactCheck(check) {
  const contract = check.evidence_contract ?? {};
  return {
    check_id: check.check_id,
    focus_area_id: check.focus_area_id,
    domain: check.domain,
    lens: check.lens,
    subject_kind: check.subject_kind,
    subject_id: check.subject_id,
    vulnerability_type_id: check.vulnerability_type_id,
    dimensions: check.dimensions,
    applicability_reason: check.applicability_reason,
    negative_discovery_required: check.negative_discovery_required,
    required_source_count: check.required_source_file_ids?.length ?? 0,
    required_interface_count: check.required_interface_ids?.length ?? 0,
    required_catalog_count: check.required_catalog_ids?.length ?? 0,
    receipt_source_scope: "required",
    evidence_contract: {
      question_field: contract.question_field,
      question: contract.question,
      required_receipt_fields: contract.required_receipt_fields,
    },
  };
}

function compactPacket(packet) {
  return {
    ...compactCheck(packet.check),
    execution_state: packet.execution_state,
    result_state: packet.result_state,
    receipt_count: packet.receipt_ids?.length ?? 0,
    finding_count: packet.finding_ids?.length ?? 0,
  };
}

function compactGap(packet) {
  const check = packet.check;
  return {
    check_id: check.check_id,
    focus_area_id: check.focus_area_id,
    domain: check.domain,
    lens: check.lens,
    subject_kind: check.subject_kind,
    subject_id: check.subject_id,
    vulnerability_type_id: check.vulnerability_type_id,
    dimensions: check.dimensions,
    execution_state: packet.execution_state,
    result_state: packet.result_state,
    required_source_count: check.required_source_file_ids?.length ?? 0,
  };
}

function compactEvent(event, identifier) {
  return {
    ...(identifier ? { [identifier]: event[identifier] } : {}),
    sequence: event.sequence,
    event_type: event.event_type,
    event_hash: event.event_hash,
    recorded_at: event.recorded_at,
  };
}

function compactReceipt(event) {
  const sourceEvidence = event.source_hashes;
  const explicitSources = Array.isArray(sourceEvidence);
  return {
    ...compactEvent(event, "receipt_id"),
    source_scope: explicitSources ? "explicit" : "required",
    source_count: explicitSources ? sourceEvidence.length : sourceEvidence?.source_count,
    source_set_sha256: explicitSources ? null : sourceEvidence?.source_set_sha256,
  };
}

function compactSource(source) {
  return {
    file_id: source.file_id,
    path: source.path,
    type: source.type,
    sha256: source.sha256,
    link_target: source.link_target,
    owner_agent: source.owner_agent,
  };
}

const server = new McpServer({
  name: "coverage_ledger",
  version: "2.0.0",
}, {
  capabilities: { tools: {} },
});

server.registerTool("coverage_get_packet", {
  description: "Return one small page of unresolved REQUIRED coverage-check summaries. Use coverage_inspect_subject for one check's detail and coverage_get_subject_sources for its paginated frozen sources.",
  inputSchema: {
    audit_id: auditIdSchema,
    focus_area_id: z.string().max(255).optional(),
    domain: z.string().max(255).optional(),
    lens: z.enum(["sink-driven", "control-driven", "config-driven"]).optional(),
    subject_kind: z.enum(["catalog-domain", "interface"]).optional(),
    cursor: cursorSchema.optional(),
    limit: z.number().int().min(1).max(10).optional(),
  },
}, async ({ audit_id, focus_area_id, domain, lens, subject_kind, cursor, limit }) => {
  const { planPath, ledgerPath } = paths(audit_id);
  const result = await serialized(() => getPackets({
    planPath,
    ledgerPath,
    focusAreaId: focus_area_id,
    domain,
    lens,
    subjectKind: subject_kind,
    cursor,
    limit: limit ?? 1,
  }));
  return textResult({
    audit_id: result.audit_id,
    plan_digest: result.plan_digest,
    total: result.total,
    returned: result.packets.length,
    next_cursor: result.next_cursor,
    packets: result.packets.map(compactPacket),
  });
});

server.registerTool("coverage_inspect_subject", {
  description: "Record that a session inspected one REQUIRED check and return only its compact immutable packet. Record full-check evidence with source_scope=required; fetch source pages only for targeted diagnostics. N/A decisions cannot be submitted through this service.",
  inputSchema: {
    audit_id: auditIdSchema,
    check_id: checkIdSchema,
    session_id: sessionIdSchema,
    idempotency_key: idempotencyKeySchema,
  },
}, async ({ audit_id, check_id, session_id, idempotency_key }) => {
  const { planPath, ledgerPath } = paths(audit_id);
  const result = await serialized(() => inspectSubject({
    planPath,
    ledgerPath,
    checkId: check_id,
    sessionId: session_id,
    idempotencyKey: idempotency_key,
  }));
  return textResult({
    audit_id,
    check: compactCheck(result.check),
    inspection: compactEvent(result.event),
    idempotent_replay: result.idempotent_replay,
  });
});

server.registerTool("coverage_get_subject_sources", {
  description: "Return one small cursor-paginated page of frozen source metadata for targeted diagnostics only. Do not enumerate a check's full source universe to create a receipt; use source_scope=required instead.",
  inputSchema: {
    audit_id: auditIdSchema,
    check_id: checkIdSchema,
    cursor: cursorSchema.optional(),
    limit: z.number().int().min(1).max(25).optional(),
  },
}, async ({ audit_id, check_id, cursor, limit }) => {
  const { planPath, ledgerPath } = paths(audit_id);
  const result = await serialized(() => getSubjectSources({
    planPath,
    ledgerPath,
    checkId: check_id,
    cursor,
    limit,
  }));
  return textResult({
    audit_id: result.audit_id,
    plan_digest: result.plan_digest,
    check_id: result.check_id,
    total_sources: result.total_sources,
    returned: result.sources.length,
    next_cursor: result.next_cursor,
    sources: result.sources.map(compactSource),
  });
});

server.registerTool("coverage_record_tool_result", {
  description: "Create one digest-bound evidence receipt. Normally pass source_scope=required so the service binds the complete frozen source universe without returning or accepting its file list. Explicit source hashes/IDs remain available for partial or legacy receipts.",
  inputSchema: {
    audit_id: auditIdSchema,
    check_id: checkIdSchema,
    session_id: sessionIdSchema,
    idempotency_key: idempotencyKeySchema,
    source_hashes: z.array(sourceHashSchema).min(1).max(MAX_BATCH_ITEMS).optional(),
    source_file_ids: z.array(z.string().max(255)).min(1).max(MAX_BATCH_ITEMS).optional(),
    source_scope: z.literal("required").optional(),
    locators: z.array(locatorSchema).min(1).max(MAX_BATCH_ITEMS),
    query_or_rule: z.string().min(1).max(8192),
    tool: z.string().min(1).max(256),
    result_digest: z.string().length(64),
    result_summary: z.string().max(4096).optional(),
  },
}, async input => {
  const sourceInputs = [input.source_hashes, input.source_file_ids, input.source_scope]
    .filter(value => value !== undefined);
  if (sourceInputs.length !== 1) {
    throw new Error("Provide exactly one of source_hashes, source_file_ids, or source_scope");
  }
  if (input.source_hashes) assertJsonSize(input.source_hashes, "source_hashes", MAX_ID_LIST_BYTES);
  if (input.source_file_ids) assertJsonSize(input.source_file_ids, "source_file_ids", MAX_ID_LIST_BYTES);
  assertJsonSize(input.locators, "locators", MAX_LOCATORS_BYTES);
  const { planPath, ledgerPath } = paths(input.audit_id);
  const result = await serialized(() => recordToolResult({
    planPath,
    ledgerPath,
    checkId: input.check_id,
    sessionId: input.session_id,
    idempotencyKey: input.idempotency_key,
    sourceHashes: input.source_hashes,
    sourceFileIds: input.source_file_ids,
    sourceScope: input.source_scope,
    locators: input.locators,
    queryOrRule: input.query_or_rule,
    tool: input.tool,
    resultDigest: input.result_digest,
    resultSummary: input.result_summary,
  }));
  return textResult({
    audit_id: input.audit_id,
    check_id: input.check_id,
    receipt: compactReceipt(result.receipt),
    idempotent_replay: result.idempotent_replay,
  });
});

server.registerTool("coverage_submit_decision", {
  description: "Submit VERIFIED, GAP, or INVALIDATED plus an independent result state. VERIFIED requires a receipt generated for the same check. Planner-only N/A is rejected.",
  inputSchema: {
    audit_id: auditIdSchema,
    check_id: checkIdSchema,
    session_id: sessionIdSchema,
    idempotency_key: idempotencyKeySchema,
    execution_state: z.enum(["VERIFIED", "GAP", "INVALIDATED"]),
    result_state: z.enum(["NO_FINDING", "FINDING", "INCONCLUSIVE"]),
    receipt_ids: z.array(z.string().max(255)).max(MAX_BATCH_ITEMS).optional(),
    finding_ids: z.array(z.string().max(255)).max(MAX_BATCH_ITEMS).optional(),
    rationale: z.string().min(1).max(8192),
  },
}, async input => {
  if (input.receipt_ids) assertJsonSize(input.receipt_ids, "receipt_ids", MAX_ID_LIST_BYTES);
  if (input.finding_ids) assertJsonSize(input.finding_ids, "finding_ids", MAX_ID_LIST_BYTES);
  const { planPath, ledgerPath } = paths(input.audit_id);
  const result = await serialized(() => submitDecision({
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
  }));
  return textResult({
    audit_id: input.audit_id,
    check_id: input.check_id,
    decision: compactEvent(result.decision),
    idempotent_replay: result.idempotent_replay,
  });
});

server.registerTool("coverage_get_gaps", {
  description: "Return a cursor-paginated compact summary of REQUIRED checks whose latest execution state is not VERIFIED.",
  inputSchema: {
    audit_id: auditIdSchema,
    cursor: cursorSchema.optional(),
    limit: z.number().int().min(1).max(20).optional(),
  },
}, async ({ audit_id, cursor, limit }) => {
  const { planPath, ledgerPath } = paths(audit_id);
  const result = await serialized(() => getGaps({ planPath, ledgerPath, cursor, limit: limit ?? 10 }));
  return textResult({
    audit_id: result.audit_id,
    required: result.required,
    verified: result.verified,
    total_gaps: result.total_gaps,
    returned: result.gaps.length,
    next_cursor: result.next_cursor,
    gaps: result.gaps.map(compactGap),
  });
});

server.registerTool("coverage_finalize", {
  description: "Finalize and seal the ledger only when the frozen plan has no UNKNOWN applicability and every REQUIRED check is VERIFIED.",
  inputSchema: {
    audit_id: auditIdSchema,
    idempotency_key: idempotencyKeySchema,
  },
}, async ({ audit_id, idempotency_key }) => {
  const { planPath, ledgerPath } = paths(audit_id);
  const result = await serialized(() => finalizeLedger({
    planPath,
    ledgerPath,
    idempotencyKey: idempotency_key,
  }));
  return textResult({
    audit_id,
    finalization: compactEvent(result.finalization),
    idempotent_replay: result.idempotent_replay,
  });
});

const transport = new StdioServerTransport();
await server.connect(transport);
