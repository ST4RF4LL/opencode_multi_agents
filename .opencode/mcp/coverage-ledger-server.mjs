#!/usr/bin/env node

import { McpServer } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js";
import { StdioServerTransport } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js";
import { z } from "../node_modules/zod/index.js";
import { resolve } from "node:path";
import {
  canonicalCoveragePaths,
  checkpointLedger,
  delegateAssignment,
  ensureWithinWorkspace,
  finalizePartialLedger,
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
const auditQueues = new Map();

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

function serialized(auditId, operation) {
  const current = auditQueues.get(auditId) ?? Promise.resolve();
  const queued = current.then(operation, operation);
  const settled = queued.then(() => undefined, () => undefined);
  auditQueues.set(auditId, settled);
  settled.finally(() => {
    if (auditQueues.get(auditId) === settled) auditQueues.delete(auditId);
  });
  return queued;
}

const locatorSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("required-source-set"),
    check_id: z.string().max(255),
    source_set_id: z.string().max(255),
    source_count: z.number().int().min(1),
  }),
  z.object({
    kind: z.literal("source-location"),
    path: z.string().min(1).max(4096),
    line_start: z.number().int().min(1),
    line_end: z.number().int().min(1).optional(),
  }),
  z.object({
    kind: z.literal("query-match"),
    path: z.string().min(1).max(4096),
    line_start: z.number().int().min(1),
    match_sha256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  }),
  z.object({
    kind: z.literal("function-location"),
    function_id: z.string().min(1).max(255),
    path: z.string().min(1).max(4096),
    line_start: z.number().int().min(1),
  }),
  z.object({
    kind: z.literal("artifact-location"),
    path: z.string().min(1).max(4096),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
  }),
]);
const findingArtifactSchema = z.object({
  finding_id: z.string().min(1).max(255),
  path: z.string().min(1).max(4096),
});
const auditIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._-]{2,127}$/i, "Invalid audit_id");
const checkIdSchema = z.string().min(1).max(255);
const sessionIdSchema = z.string().min(3).max(255);
const assignmentTokenSchema = z.string().min(32).max(512);
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
    required_source_set_id: check.required_source_set_id,
    required_source_count: check.required_source_count ?? 0,
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
    required_source_count: check.required_source_count ?? 0,
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
  const sourceEvidence = event.source_set;
  return {
    ...compactEvent(event, "receipt_id"),
    source_scope: "required",
    source_set_id: sourceEvidence?.source_set_id,
    source_count: sourceEvidence?.source_count,
    source_set_sha256: sourceEvidence?.source_set_sha256,
    result_digest: event.result_attestation?.sha256,
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
  version: "3.0.0",
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
  const result = await serialized(audit_id, () => getPackets({
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
    agent_name: z.string().min(1).max(255),
    idempotency_key: idempotencyKeySchema,
  },
}, async ({ audit_id, check_id, session_id, agent_name, idempotency_key }) => {
  const { planPath, ledgerPath } = paths(audit_id);
  const result = await serialized(audit_id, () => inspectSubject({
    planPath,
    ledgerPath,
    checkId: check_id,
    sessionId: session_id,
    agentName: agent_name,
    idempotencyKey: idempotency_key,
  }));
  return textResult({
    audit_id,
    check: compactCheck(result.check),
    inspection: compactEvent(result.event),
    assignment_token: result.assignment_token,
    idempotent_replay: result.idempotent_replay,
  });
});

server.registerTool("coverage_delegate_assignment", {
  description: "Explicitly hand one check assignment to another session. The current assignment token is consumed only as authorization; a new scoped token is returned.",
  inputSchema: {
    audit_id: auditIdSchema,
    check_id: checkIdSchema,
    session_id: sessionIdSchema,
    assignment_token: assignmentTokenSchema,
    target_session_id: sessionIdSchema,
    idempotency_key: idempotencyKeySchema,
  },
}, async input => {
  const { planPath, ledgerPath } = paths(input.audit_id);
  const result = await serialized(input.audit_id, () => delegateAssignment({
    planPath,
    ledgerPath,
    checkId: input.check_id,
    sessionId: input.session_id,
    assignmentToken: input.assignment_token,
    targetSessionId: input.target_session_id,
    idempotencyKey: input.idempotency_key,
  }));
  return textResult({
    audit_id: input.audit_id,
    check_id: input.check_id,
    delegation: compactEvent(result.delegation),
    assignment_token: result.assignment_token,
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
  const result = await serialized(audit_id, () => getSubjectSources({
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
  description: "Create one v3 evidence receipt bound to a server-issued assignment, the complete frozen source set, typed locators, tool version, and a result digest derived by the service.",
  inputSchema: {
    audit_id: auditIdSchema,
    check_id: checkIdSchema,
    session_id: sessionIdSchema,
    assignment_token: assignmentTokenSchema,
    idempotency_key: idempotencyKeySchema,
    source_scope: z.literal("required"),
    locators: z.array(locatorSchema).min(1).max(MAX_BATCH_ITEMS),
    query_or_rule: z.string().min(1).max(8192),
    tool: z.string().min(1).max(256),
    tool_version: z.string().min(1).max(256),
    result_payload: z.string().max(64 * 1024).optional(),
    result_artifact_path: z.string().min(1).max(4096).optional(),
    result_digest: z.string().regex(/^[a-f0-9]{64}$/).optional(),
    result_summary: z.string().max(4096).optional(),
  },
}, async input => {
  if ([input.result_payload, input.result_artifact_path].filter(value => value !== undefined).length !== 1) {
    throw new Error("Provide exactly one of result_payload or result_artifact_path");
  }
  assertJsonSize(input.locators, "locators", MAX_LOCATORS_BYTES);
  const { planPath, ledgerPath } = paths(input.audit_id);
  const result = await serialized(input.audit_id, () => recordToolResult({
    planPath,
    ledgerPath,
    checkId: input.check_id,
    sessionId: input.session_id,
    assignmentToken: input.assignment_token,
    idempotencyKey: input.idempotency_key,
    sourceScope: input.source_scope,
    locators: input.locators,
    queryOrRule: input.query_or_rule,
    tool: input.tool,
    toolVersion: input.tool_version,
    resultPayload: input.result_payload,
    resultArtifactPath: input.result_artifact_path
      ? ensureWithinWorkspace(WORKSPACE_ROOT, input.result_artifact_path)
      : undefined,
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
  description: "Submit VERIFIED, GAP, or INVALIDATED under the active assignment. VERIFIED requires an authorized same-check receipt; FINDING additionally requires server-verified finding artifacts.",
  inputSchema: {
    audit_id: auditIdSchema,
    check_id: checkIdSchema,
    session_id: sessionIdSchema,
    assignment_token: assignmentTokenSchema,
    idempotency_key: idempotencyKeySchema,
    execution_state: z.enum(["VERIFIED", "GAP", "INVALIDATED"]),
    result_state: z.enum(["NO_FINDING", "FINDING", "INCONCLUSIVE"]),
    receipt_ids: z.array(z.string().max(255)).max(MAX_BATCH_ITEMS).optional(),
    finding_ids: z.array(z.string().max(255)).max(MAX_BATCH_ITEMS).optional(),
    finding_artifacts: z.array(findingArtifactSchema).max(MAX_BATCH_ITEMS).optional(),
    rationale: z.string().min(1).max(8192),
  },
}, async input => {
  if (input.receipt_ids) assertJsonSize(input.receipt_ids, "receipt_ids", MAX_ID_LIST_BYTES);
  if (input.finding_ids) assertJsonSize(input.finding_ids, "finding_ids", MAX_ID_LIST_BYTES);
  const { planPath, ledgerPath } = paths(input.audit_id);
  if (input.finding_artifacts) assertJsonSize(input.finding_artifacts, "finding_artifacts", MAX_LOCATORS_BYTES);
  const result = await serialized(input.audit_id, () => submitDecision({
    planPath,
    ledgerPath,
    checkId: input.check_id,
    sessionId: input.session_id,
    assignmentToken: input.assignment_token,
    idempotencyKey: input.idempotency_key,
    executionState: input.execution_state,
    resultState: input.result_state,
    receiptIds: input.receipt_ids ?? [],
    findingIds: input.finding_ids ?? [],
    findingArtifacts: (input.finding_artifacts ?? []).map(item => ({
      ...item,
      path: ensureWithinWorkspace(WORKSPACE_ROOT, item.path),
    })),
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
  const result = await serialized(audit_id, () => getGaps({ planPath, ledgerPath, cursor, limit: limit ?? 10 }));
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

server.registerTool("coverage_checkpoint", {
  description: "Seal an immutable partial checkpoint at the current chain head without claiming complete coverage or preventing later work.",
  inputSchema: {
    audit_id: auditIdSchema,
    idempotency_key: idempotencyKeySchema,
    label: z.string().min(1).max(255).optional(),
  },
}, async ({ audit_id, idempotency_key, label }) => {
  const { planPath, ledgerPath } = paths(audit_id);
  const result = await serialized(audit_id, () => checkpointLedger({
    planPath,
    ledgerPath,
    idempotencyKey: idempotency_key,
    label: label ?? "partial",
  }));
  return textResult({
    audit_id,
    checkpoint: compactEvent(result.checkpoint),
    seal_state: "PARTIAL_CHECKPOINT",
    idempotent_replay: result.idempotent_replay,
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
  const result = await serialized(audit_id, () => finalizeLedger({
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

server.registerTool("coverage_finalize_partial", {
  description: "Terminally seal a partial ledger only after an explicit budget, round-limit, or operator-stop decision; it never authorizes a complete-coverage claim.",
  inputSchema: {
    audit_id: auditIdSchema,
    idempotency_key: idempotencyKeySchema,
    termination_reason: z.enum(["budget-exhausted", "round-limit-reached", "operator-stop"]),
  },
}, async ({ audit_id, idempotency_key, termination_reason }) => {
  const { planPath, ledgerPath } = paths(audit_id);
  const result = await serialized(audit_id, () => finalizePartialLedger({
    planPath,
    ledgerPath,
    idempotencyKey: idempotency_key,
    terminationReason: termination_reason,
  }));
  return textResult({
    audit_id,
    finalization: compactEvent(result.finalization),
    seal_state: "FINALIZED_PARTIAL",
    idempotent_replay: result.idempotent_replay,
  });
});

const transport = new StdioServerTransport();
await server.connect(transport);
