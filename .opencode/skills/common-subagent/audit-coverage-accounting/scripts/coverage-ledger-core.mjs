import { appendFile, mkdir, readFile, stat } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { objectDigest, sha256, validatePlan } from "./coverage-v2-common.mjs";

export function canonicalCoveragePaths(workspaceRoot, auditId) {
  if (!/^[a-z0-9][a-z0-9._-]{2,127}$/i.test(auditId)) throw new Error(`Invalid audit_id: ${auditId}`);
  const root = resolve(workspaceRoot);
  return {
    planPath: join(root, "reports", "coverage", `coverage-plan.${auditId}.json`),
    ledgerPath: join(root, "reports", "coverage", auditId, "ledger", "coverage-ledger.jsonl"),
    summaryPath: join(root, "reports", "coverage", `coverage-summary.${auditId}.json`),
  };
}

export function ensureWithinWorkspace(workspaceRoot, path) {
  const root = resolve(workspaceRoot);
  const absolute = resolve(path);
  const rel = relative(root, absolute);
  if (rel.startsWith("..") || rel === "") {
    if (absolute === root) throw new Error("Canonical coverage artifact cannot be the workspace root");
    if (rel.startsWith("..")) throw new Error(`Path escapes workspace: ${path}`);
  }
  return absolute;
}

function eventDigest(event) {
  const copy = { ...event };
  delete copy.event_hash;
  return sha256(JSON.stringify(copy));
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

export async function loadPlan(planPath) {
  const plan = await readJson(resolve(planPath));
  const errors = validatePlan(plan);
  if (errors.length > 0) throw new Error(`Coverage plan is invalid:\n- ${errors.join("\n- ")}`);
  return plan;
}

export async function readLedger(ledgerPath, { allowMissing = false } = {}) {
  let text;
  try {
    text = await readFile(resolve(ledgerPath), "utf8");
  } catch (error) {
    if (allowMissing && error.code === "ENOENT") return [];
    throw error;
  }
  const events = text.split(/\r?\n/).filter(Boolean).map((line, index) => {
    try {
      return JSON.parse(line);
    } catch (error) {
      throw new Error(`Invalid ledger JSON at line ${index + 1}: ${error.message}`);
    }
  });
  let previousHash = null;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (event.sequence !== index) throw new Error(`Ledger sequence mismatch at line ${index + 1}`);
    if (event.previous_hash !== previousHash) throw new Error(`Ledger previous_hash mismatch at line ${index + 1}`);
    if (event.event_hash !== eventDigest(event)) throw new Error(`Ledger hash mismatch at line ${index + 1}`);
    previousHash = event.event_hash;
  }
  if (events.length > 0 && events[0].event_type !== "GENESIS") throw new Error("Ledger must begin with GENESIS");
  return events;
}

function makeEvent(events, eventType, body) {
  const event = {
    sequence: events.length,
    previous_hash: events.at(-1)?.event_hash ?? null,
    event_type: eventType,
    recorded_at: new Date().toISOString(),
    ...body,
  };
  event.event_hash = eventDigest(event);
  return event;
}

async function appendEvent(path, events, eventType, body) {
  const event = makeEvent(events, eventType, body);
  await mkdir(dirname(resolve(path)), { recursive: true });
  await appendFile(resolve(path), `${JSON.stringify(event)}\n`, { encoding: "utf8", flag: "a" });
  return event;
}

function sameIdempotentOperation(event, eventType, body) {
  if (event.event_type !== eventType) return false;
  const comparable = { ...body };
  delete comparable.idempotency_key;
  return Object.entries(comparable).every(([key, value]) => JSON.stringify(event[key]) === JSON.stringify(value));
}

function findIdempotent(events, eventType, body) {
  if (!body.idempotency_key) throw new Error("idempotency_key is required");
  const prior = events.find(event => event.idempotency_key === body.idempotency_key);
  if (!prior) return null;
  if (!sameIdempotentOperation(prior, eventType, body)) throw new Error(`Conflicting reuse of idempotency_key: ${body.idempotency_key}`);
  return prior;
}

function requireMutable(events) {
  if (events.some(event => event.event_type === "FINALIZE")) throw new Error("Coverage ledger is finalized and immutable");
}

function validateLedgerBinding(events, plan) {
  if (events.length === 0) throw new Error("Coverage ledger is not initialized");
  const genesis = events[0];
  if (genesis.audit_id !== plan.audit_id || genesis.plan_digest !== plan.manifest_digest || genesis.scope_digest !== plan.scope_digest) {
    throw new Error("Coverage ledger genesis does not match the frozen plan");
  }
  for (const event of events) {
    if (event.audit_id !== plan.audit_id || event.plan_digest !== plan.manifest_digest) {
      throw new Error(`Stale or foreign ledger event at sequence ${event.sequence}`);
    }
  }
}

export async function initializeLedger({ planPath, ledgerPath }) {
  const plan = await loadPlan(planPath);
  const events = await readLedger(ledgerPath, { allowMissing: true });
  if (events.length > 0) {
    validateLedgerBinding(events, plan);
    return { plan, events, genesis: events[0], initialized: false };
  }
  const genesis = await appendEvent(ledgerPath, [], "GENESIS", {
    audit_id: plan.audit_id,
    plan_digest: plan.manifest_digest,
    scope_digest: plan.scope_digest,
    catalog_profile_id: plan.catalog_profile_id,
    required_checks: plan.summary.required,
  });
  return { plan, events: [genesis], genesis, initialized: true };
}

async function boundState(planPath, ledgerPath) {
  const { plan } = await initializeLedger({ planPath, ledgerPath });
  const events = await readLedger(ledgerPath);
  validateLedgerBinding(events, plan);
  return { plan, events };
}

function checkMap(plan) {
  return new Map(plan.checks.map(check => [check.check_id, check]));
}

function requireRequiredCheck(plan, checkId) {
  const check = checkMap(plan).get(checkId);
  if (!check) throw new Error(`Unknown coverage check_id: ${checkId}`);
  if (check.applicability !== "REQUIRED") throw new Error(`Only REQUIRED checks can be executed: ${checkId}`);
  return check;
}

function validateSessionId(value) {
  if (!/^[a-z0-9][a-z0-9._:-]{2,255}$/i.test(value ?? "")) throw new Error(`Invalid session_id: ${value}`);
}

export function deriveLedgerState(plan, events) {
  const state = new Map(plan.checks.filter(check => check.applicability === "REQUIRED").map(check => [check.check_id, {
    check,
    execution_state: "PLANNED",
    result_state: null,
    receipt_ids: [],
    finding_ids: [],
    decision_sequence: null,
  }]));
  for (const event of events) {
    const current = state.get(event.check_id);
    if (!current) continue;
    if (event.event_type === "INSPECT") current.execution_state = "INSPECTED";
    if (event.event_type === "RECEIPT") {
      if (current.execution_state === "PLANNED") current.execution_state = "INSPECTED";
      current.receipt_ids.push(event.receipt_id);
    }
    if (event.event_type === "DECISION") {
      current.execution_state = event.execution_state;
      current.result_state = event.result_state;
      current.finding_ids = event.finding_ids ?? [];
      current.decision_sequence = event.sequence;
    }
  }
  return state;
}

export async function inspectSubject({ planPath, ledgerPath, checkId, sessionId, idempotencyKey }) {
  validateSessionId(sessionId);
  const { plan, events } = await boundState(planPath, ledgerPath);
  requireMutable(events);
  const check = requireRequiredCheck(plan, checkId);
  const body = {
    audit_id: plan.audit_id,
    plan_digest: plan.manifest_digest,
    check_id: checkId,
    session_id: sessionId,
    idempotency_key: idempotencyKey,
  };
  const prior = findIdempotent(events, "INSPECT", body);
  const event = prior ?? await appendEvent(ledgerPath, events, "INSPECT", body);
  return { check, event, idempotent_replay: Boolean(prior) };
}

function validateSourceHashes(plan, sourceHashes) {
  if (!Array.isArray(sourceHashes) || sourceHashes.length === 0) throw new Error("source_hashes must be a non-empty array");
  const sourceIndex = new Map((plan.source_index ?? []).map(source => [source.file_id, source]));
  for (const source of sourceHashes) {
    if (typeof source?.file_id !== "string" || !(typeof source?.sha256 === "string" || source?.sha256 === null)) {
      throw new Error("Each source_hashes row requires file_id and a SHA-256 value or null for a symlink");
    }
    const frozen = sourceIndex.get(source.file_id);
    if (!frozen || frozen.sha256 !== source.sha256
      || (frozen.sha256 === null && frozen.link_target !== source.link_target)) {
      throw new Error(`Stale or non-frozen source hash: ${source.file_id}`);
    }
  }
}

export async function recordToolResult({
  planPath,
  ledgerPath,
  checkId,
  sessionId,
  idempotencyKey,
  sourceHashes,
  locators,
  queryOrRule,
  tool,
  resultDigest,
  resultSummary,
}) {
  validateSessionId(sessionId);
  const { plan, events } = await boundState(planPath, ledgerPath);
  requireMutable(events);
  const check = requireRequiredCheck(plan, checkId);
  validateSourceHashes(plan, sourceHashes);
  if (!Array.isArray(locators) || locators.length === 0 || locators.some(locator => typeof locator !== "object" || locator == null)) {
    throw new Error("locators must be a non-empty object array");
  }
  if (typeof queryOrRule !== "string" || queryOrRule.trim() === "") throw new Error("query_or_rule is required");
  if (typeof tool !== "string" || tool.trim() === "") throw new Error("tool is required");
  if (!/^[a-f0-9]{64}$/.test(resultDigest ?? "")) throw new Error("result_digest must be a SHA-256 hex digest");
  const receiptId = `receipt:${sha256([plan.manifest_digest, checkId, sessionId, idempotencyKey].join("\n")).slice(0, 32)}`;
  const body = {
    audit_id: plan.audit_id,
    plan_digest: plan.manifest_digest,
    check_id: checkId,
    session_id: sessionId,
    idempotency_key: idempotencyKey,
    receipt_id: receiptId,
    source_hashes: sourceHashes,
    locators,
    query_or_rule: queryOrRule,
    tool,
    result_digest: resultDigest,
    result_summary: resultSummary ?? null,
  };
  const prior = findIdempotent(events, "RECEIPT", body);
  const event = prior ?? await appendEvent(ledgerPath, events, "RECEIPT", body);
  return { receipt: event, idempotent_replay: Boolean(prior) };
}

export async function submitDecision({
  planPath,
  ledgerPath,
  checkId,
  sessionId,
  idempotencyKey,
  executionState,
  resultState,
  receiptIds = [],
  findingIds = [],
  rationale,
}) {
  validateSessionId(sessionId);
  const { plan, events } = await boundState(planPath, ledgerPath);
  requireMutable(events);
  const check = requireRequiredCheck(plan, checkId);
  if (!["VERIFIED", "GAP", "INVALIDATED"].includes(executionState)) throw new Error("Decision execution_state must be VERIFIED, GAP, or INVALIDATED; N/A is planner-only");
  if (!["NO_FINDING", "FINDING", "INCONCLUSIVE"].includes(resultState)) throw new Error("Invalid decision result_state");
  if (executionState === "VERIFIED" && resultState === "INCONCLUSIVE") throw new Error("VERIFIED cannot be INCONCLUSIVE");
  if (executionState !== "VERIFIED" && resultState !== "INCONCLUSIVE") throw new Error("GAP/INVALIDATED decisions must be INCONCLUSIVE");
  if (resultState === "FINDING" && (!Array.isArray(findingIds) || findingIds.length === 0)) throw new Error("FINDING requires finding_ids");
  if (resultState !== "FINDING" && (findingIds?.length ?? 0) > 0) throw new Error("finding_ids are only valid for FINDING");
  const receiptEvents = events.filter(event => event.event_type === "RECEIPT" && event.check_id === checkId);
  const validReceipts = new Set(receiptEvents.map(event => event.receipt_id));
  if (executionState === "VERIFIED") {
    if (!Array.isArray(receiptIds) || receiptIds.length === 0) throw new Error("VERIFIED requires at least one receipt_id");
    for (const receiptId of receiptIds) if (!validReceipts.has(receiptId)) throw new Error(`Receipt is missing, stale, or belongs to another check: ${receiptId}`);
    const referencedReceipts = receiptEvents.filter(event => receiptIds.includes(event.receipt_id));
    const evidencedSources = new Set(referencedReceipts.flatMap(event => event.source_hashes.map(source => source.file_id)));
    const missingSources = check.required_source_file_ids.filter(fileId => !evidencedSources.has(fileId));
    if (missingSources.length > 0) throw new Error(`VERIFIED receipts do not cover the frozen source universe: ${missingSources.join(", ")}`);
  }
  if (typeof rationale !== "string" || rationale.trim() === "") throw new Error("Decision rationale is required");
  const body = {
    audit_id: plan.audit_id,
    plan_digest: plan.manifest_digest,
    check_id: checkId,
    session_id: sessionId,
    idempotency_key: idempotencyKey,
    execution_state: executionState,
    result_state: resultState,
    receipt_ids: receiptIds,
    finding_ids: findingIds,
    rationale,
  };
  const prior = findIdempotent(events, "DECISION", body);
  const latestState = deriveLedgerState(plan, events).get(checkId);
  if (!prior && latestState?.execution_state === "VERIFIED") {
    throw new Error(`VERIFIED decision is immutable; submit follow-up evidence under a different unresolved check: ${checkId}`);
  }
  const event = prior ?? await appendEvent(ledgerPath, events, "DECISION", body);
  return { decision: event, idempotent_replay: Boolean(prior) };
}

export async function getPackets({ planPath, ledgerPath, focusAreaId, domain, lens, subjectKind, limit = 25 }) {
  const { plan, events } = await boundState(planPath, ledgerPath);
  const state = deriveLedgerState(plan, events);
  const packets = [...state.values()]
    .filter(item => !focusAreaId || item.check.focus_area_id === focusAreaId)
    .filter(item => !domain || item.check.domain === domain)
    .filter(item => !lens || item.check.lens === lens)
    .filter(item => !subjectKind || item.check.subject_kind === subjectKind)
    .filter(item => item.execution_state !== "VERIFIED")
    .sort((a, b) => a.check.check_id.localeCompare(b.check.check_id))
    .slice(0, Math.max(1, Math.min(250, limit)));
  return { audit_id: plan.audit_id, plan_digest: plan.manifest_digest, packets };
}

export async function getGaps({ planPath, ledgerPath }) {
  const { plan, events } = await boundState(planPath, ledgerPath);
  const state = deriveLedgerState(plan, events);
  const gaps = [...state.values()].filter(item => item.execution_state !== "VERIFIED");
  return {
    audit_id: plan.audit_id,
    required: state.size,
    verified: state.size - gaps.length,
    gaps: gaps.sort((a, b) => a.check.check_id.localeCompare(b.check.check_id)),
  };
}

export async function finalizeLedger({ planPath, ledgerPath, idempotencyKey }) {
  const { plan, events } = await boundState(planPath, ledgerPath);
  const prior = events.find(event => event.event_type === "FINALIZE");
  if (prior) {
    if (prior.idempotency_key !== idempotencyKey) throw new Error("Coverage ledger is already finalized");
    return { finalization: prior, idempotent_replay: true };
  }
  if (plan.summary.unknown > 0 || !plan.complete) throw new Error("Coverage plan contains UNKNOWN applicability and cannot be finalized");
  const state = deriveLedgerState(plan, events);
  const gaps = [...state.values()].filter(item => item.execution_state !== "VERIFIED");
  if (gaps.length > 0) throw new Error(`Coverage ledger has ${gaps.length} unverified REQUIRED checks`);
  const body = {
    audit_id: plan.audit_id,
    plan_digest: plan.manifest_digest,
    idempotency_key: idempotencyKey,
    required: state.size,
    verified: state.size,
    findings: [...state.values()].filter(item => item.result_state === "FINDING").length,
    chain_head_before_finalize: events.at(-1).event_hash,
  };
  const event = await appendEvent(ledgerPath, events, "FINALIZE", body);
  return { finalization: event, idempotent_replay: false };
}

export async function verifyLedger({ planPath, ledgerPath, requireFinalized = true }) {
  const plan = await loadPlan(planPath);
  const events = await readLedger(ledgerPath);
  validateLedgerBinding(events, plan);
  const state = deriveLedgerState(plan, events);
  const finalization = events.find(event => event.event_type === "FINALIZE") ?? null;
  const gaps = [...state.values()].filter(item => item.execution_state !== "VERIFIED");
  const issues = [];
  if (plan.summary.unknown > 0) issues.push({ code: "UNKNOWN_APPLICABILITY", count: plan.summary.unknown });
  if (gaps.length > 0) issues.push({ code: "UNVERIFIED_REQUIRED_CHECKS", count: gaps.length });
  if (requireFinalized && !finalization) issues.push({ code: "LEDGER_NOT_FINALIZED" });
  if (finalization && finalization.chain_head_before_finalize !== events.at(-2)?.event_hash) issues.push({ code: "FINALIZATION_CHAIN_HEAD_MISMATCH" });
  return { plan, events, state, finalization, gaps, issues, complete: issues.length === 0 };
}

export async function fileExists(path) {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}
