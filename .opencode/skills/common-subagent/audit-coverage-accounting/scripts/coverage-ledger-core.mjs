import { createHash, createHmac, randomBytes } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { hostname } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import {
  DOMAIN_AGENTS,
  objectDigest,
  sha256,
  sourceFileIdsForCheck,
  validatePlan,
} from "./coverage-v2-common.mjs";
import { parseFindingArtifact } from "../../finding-evidence-contract/scripts/finding-contract.mjs";

const PLAN_CACHE_LIMIT = 8;
const LEDGER_CACHE_LIMIT = 16;
const LOCK_TIMEOUT_MS = 15_000;
const STALE_LOCK_MS = 30_000;
const MAX_INLINE_RESULT_BYTES = 64 * 1024;
const MAX_RESULT_ARTIFACT_BYTES = 64 * 1024 * 1024;
const MAX_FINDING_ARTIFACT_BYTES = 4 * 1024 * 1024;
const PLAN_CACHE = new Map();
const LEDGER_CACHE = new Map();
const KEY_CACHE = new Map();
const CHECK_MAP_CACHE = new WeakMap();
const STATE_CACHE = new Map();

export function canonicalCoveragePaths(workspaceRoot, auditId) {
  if (!/^[a-z0-9][a-z0-9._-]{2,127}$/i.test(auditId)) throw new Error(`Invalid audit_id: ${auditId}`);
  const root = resolve(workspaceRoot);
  return {
    planPath: join(root, "reports", "coverage", `coverage-plan.${auditId}.json`),
    ledgerPath: join(root, "reports", "coverage", auditId, "ledger", "coverage-ledger.jsonl"),
    summaryPath: join(root, "reports", "coverage", `coverage-summary.${auditId}.json`),
    summaryMarkdownPath: join(root, "reports", "coverage", `coverage-summary.${auditId}.md`),
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

function cacheSet(cache, key, value, limit) {
  cache.delete(key);
  cache.set(key, value);
  while (cache.size > limit) cache.delete(cache.keys().next().value);
}

function statKey(value) {
  return [value.dev, value.ino, value.size, value.mtimeMs, value.ctimeMs].join(":");
}

function eventDigest(event) {
  const copy = { ...event };
  delete copy.event_hash;
  delete copy.event_hmac;
  return sha256(JSON.stringify(copy));
}

function eventHmac(secret, eventHash) {
  return createHmac("sha256", secret).update(eventHash).digest("hex");
}

function keyPath(ledgerPath) {
  return `${resolve(ledgerPath)}.key`;
}

async function readLedgerSecret(path) {
  const metadata = await stat(path);
  const key = statKey(metadata);
  const cached = KEY_CACHE.get(path);
  if (cached?.stat_key === key) {
    cacheSet(KEY_CACHE, path, cached, LEDGER_CACHE_LIMIT);
    return cached.secret;
  }
  const secret = await readFile(path);
  if (secret.length !== 32) throw new Error(`Coverage ledger key has an invalid length: ${path}`);
  if ((metadata.mode & 0o077) !== 0) throw new Error(`Coverage ledger key permissions must be 0600: ${path}`);
  cacheSet(KEY_CACHE, path, { stat_key: key, secret }, LEDGER_CACHE_LIMIT);
  return secret;
}

async function ledgerSecret(ledgerPath, { create = false } = {}) {
  const path = keyPath(ledgerPath);
  try {
    return await readLedgerSecret(path);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    if (!create) throw new Error(`Coverage ledger key is missing or unreadable: ${path}`);
  }
  await mkdir(dirname(path), { recursive: true });
  const secret = randomBytes(32);
  let handle;
  try {
    handle = await open(path, "wx", 0o600);
    await handle.writeFile(secret);
    await handle.sync();
    const metadata = await handle.stat();
    cacheSet(KEY_CACHE, path, { stat_key: statKey(metadata), secret }, LEDGER_CACHE_LIMIT);
    return secret;
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    return readLedgerSecret(path);
  } finally {
    await handle?.close();
  }
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

export async function loadPlan(planPath) {
  const path = resolve(planPath);
  const metadata = await stat(path);
  const key = statKey(metadata);
  const cached = PLAN_CACHE.get(path);
  if (cached?.stat_key === key) {
    cacheSet(PLAN_CACHE, path, cached, PLAN_CACHE_LIMIT);
    return cached.plan;
  }
  const plan = await readJson(path);
  const errors = validatePlan(plan);
  if (errors.length > 0) {
    const shown = errors.slice(0, 20);
    const remainder = errors.length - shown.length;
    throw new Error(`Coverage plan is invalid:\n- ${shown.join("\n- ")}${remainder > 0 ? `\n- ... ${remainder} additional validation errors omitted` : ""}`);
  }
  cacheSet(PLAN_CACHE, path, { stat_key: key, plan }, PLAN_CACHE_LIMIT);
  return plan;
}

function validateEvents(events, secret) {
  let previousHash = null;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (event.sequence !== index) throw new Error(`Ledger sequence mismatch at line ${index + 1}`);
    if (event.previous_hash !== previousHash) throw new Error(`Ledger previous_hash mismatch at line ${index + 1}`);
    if (event.event_hash !== eventDigest(event)) throw new Error(`Ledger hash mismatch at line ${index + 1}`);
    if (event.event_hmac !== eventHmac(secret, event.event_hash)) throw new Error(`Ledger HMAC mismatch at line ${index + 1}`);
    previousHash = event.event_hash;
  }
  if (events.length > 0 && events[0].event_type !== "GENESIS") throw new Error("Ledger must begin with GENESIS");
}

export async function readLedger(ledgerPath, { allowMissing = false } = {}) {
  const path = resolve(ledgerPath);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    let metadata;
    try {
      metadata = await stat(path);
    } catch (error) {
      if (allowMissing && error.code === "ENOENT") {
        LEDGER_CACHE.delete(path);
        return [];
      }
      throw error;
    }
    let secretMetadata;
    try {
      secretMetadata = await stat(keyPath(path));
    } catch (error) {
      throw new Error(`Coverage ledger key is missing or unreadable: ${keyPath(path)}`, { cause: error });
    }
    const cacheKey = `${statKey(metadata)}|${statKey(secretMetadata)}`;
    const cached = LEDGER_CACHE.get(path);
    if (cached?.stat_key === cacheKey) {
      cacheSet(LEDGER_CACHE, path, cached, LEDGER_CACHE_LIMIT);
      return cached.events;
    }
    const text = await readFile(path, "utf8");
    const [stableLedgerMetadata, stableSecretMetadata] = await Promise.all([
      stat(path),
      stat(keyPath(path)),
    ]);
    const stableCacheKey = `${statKey(stableLedgerMetadata)}|${statKey(stableSecretMetadata)}`;
    if (stableCacheKey !== cacheKey) {
      if (attempt < 2) {
        await new Promise(resolveWait => setTimeout(resolveWait, 10));
        continue;
      }
      throw new Error("Coverage ledger changed during all stable-read attempts");
    }
    const lines = text.split(/\r?\n/);
    if (lines.at(-1) !== "") {
      if (attempt < 2) {
        await new Promise(resolveWait => setTimeout(resolveWait, 10));
        continue;
      }
      throw new Error("Coverage ledger ends with an incomplete event");
    }
    let events;
    try {
      events = lines.filter(Boolean).map((line, index) => {
        try {
          return JSON.parse(line);
        } catch (error) {
          throw new Error(`Invalid ledger JSON at line ${index + 1}: ${error.message}`);
        }
      });
    } catch (error) {
      if (attempt < 2) {
        await new Promise(resolveWait => setTimeout(resolveWait, 10));
        continue;
      }
      throw error;
    }
    const secret = await ledgerSecret(path);
    validateEvents(events, secret);
    cacheSet(LEDGER_CACHE, path, { stat_key: stableCacheKey, events }, LEDGER_CACHE_LIMIT);
    return events;
  }
  throw new Error("Coverage ledger could not be read consistently");
}

function makeEvent(events, eventType, body, secret) {
  const event = {
    sequence: events.length,
    previous_hash: events.at(-1)?.event_hash ?? null,
    event_type: eventType,
    recorded_at: new Date().toISOString(),
    ...body,
  };
  event.event_hash = eventDigest(event);
  event.event_hmac = eventHmac(secret, event.event_hash);
  return event;
}

async function appendEvent(path, events, eventType, body) {
  const ledgerPath = resolve(path);
  const secret = await ledgerSecret(ledgerPath, { create: true });
  const event = makeEvent(events, eventType, body, secret);
  await mkdir(dirname(ledgerPath), { recursive: true });
  const handle = await open(ledgerPath, "a", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(event)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  const metadata = await stat(ledgerPath);
  const secretMetadata = await stat(keyPath(ledgerPath));
  const nextEvents = [...events, event];
  cacheSet(LEDGER_CACHE, ledgerPath, {
    stat_key: `${statKey(metadata)}|${statKey(secretMetadata)}`,
    events: nextEvents,
  }, LEDGER_CACHE_LIMIT);
  return event;
}

function processExists(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === "EPERM";
  }
}

async function staleLock(lockPath) {
  try {
    const metadata = await stat(lockPath);
    if (Date.now() - metadata.mtimeMs < STALE_LOCK_MS) return false;
    let owner = null;
    try {
      owner = JSON.parse(await readFile(join(lockPath, "owner.json"), "utf8"));
    } catch {
      owner = null;
    }
    if (owner?.host === hostname() && processExists(owner.pid)) return false;
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

async function withLedgerLock(ledgerPath, operation) {
  const path = resolve(ledgerPath);
  const lockPath = `${path}.lock`;
  await mkdir(dirname(path), { recursive: true });
  const started = Date.now();
  while (true) {
    try {
      await mkdir(lockPath);
      try {
        await writeFile(join(lockPath, "owner.json"), `${JSON.stringify({
          pid: process.pid,
          host: hostname(),
          acquired_at: new Date().toISOString(),
        })}\n`, { encoding: "utf8", mode: 0o600 });
      } catch (ownerError) {
        await rm(lockPath, { recursive: true, force: true });
        throw ownerError;
      }
      break;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      if (await staleLock(lockPath)) {
        const stalePath = `${lockPath}.stale.${process.pid}.${Date.now()}`;
        try {
          await rename(lockPath, stalePath);
          await rm(stalePath, { recursive: true, force: true });
        } catch (renameError) {
          if (renameError.code !== "ENOENT") throw renameError;
        }
        continue;
      }
      if (Date.now() - started >= LOCK_TIMEOUT_MS) throw new Error(`Timed out waiting for coverage ledger transaction lock: ${lockPath}`);
      await new Promise(resolveWait => setTimeout(resolveWait, 25));
    }
  }
  try {
    return await operation();
  } finally {
    await rm(lockPath, { recursive: true, force: true });
  }
}

function sameIdempotentOperation(event, eventType, body) {
  if (event.event_type !== eventType) return false;
  const comparable = { ...body };
  delete comparable.idempotency_key;
  delete comparable.chain_head_before_checkpoint;
  delete comparable.chain_head_before_finalize;
  delete comparable.chain_head_before_terminal;
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
  if (events.some(event => ["FINALIZE_COMPLETE", "FINALIZE_PARTIAL"].includes(event.event_type))) {
    throw new Error("Coverage ledger is finalized and immutable");
  }
}

function validateLedgerBinding(events, plan) {
  if (events.length === 0) throw new Error("Coverage ledger is not initialized");
  const genesis = events[0];
  if (genesis.schema_version !== 3 || genesis.audit_id !== plan.audit_id
    || genesis.plan_digest !== plan.manifest_digest || genesis.scope_digest !== plan.scope_digest
    || genesis.snapshot_digest !== plan.inputs.snapshot_digest) {
    throw new Error("Coverage ledger genesis does not match the frozen v3 plan");
  }
  for (const event of events) {
    if (event.audit_id !== plan.audit_id || event.plan_digest !== plan.manifest_digest) {
      throw new Error(`Stale or foreign ledger event at sequence ${event.sequence}`);
    }
  }
}

async function initializeEvents(plan, ledgerPath) {
  const events = await readLedger(ledgerPath, { allowMissing: true });
  if (events.length > 0) {
    validateLedgerBinding(events, plan);
    return { events, genesis: events[0], initialized: false };
  }
  await ledgerSecret(ledgerPath, { create: true });
  const genesis = await appendEvent(ledgerPath, [], "GENESIS", {
    schema_version: 3,
    audit_id: plan.audit_id,
    plan_digest: plan.manifest_digest,
    scope_digest: plan.scope_digest,
    snapshot_digest: plan.inputs.snapshot_digest,
    catalog_profile_id: plan.catalog_profile_id,
    coverage_model_version: plan.coverage_model_version,
    required_checks: plan.summary.required,
  });
  return { events: [genesis], genesis, initialized: true };
}

export async function initializeLedger({ planPath, ledgerPath }) {
  const plan = await loadPlan(planPath);
  return withLedgerLock(ledgerPath, async () => {
    const initialized = await initializeEvents(plan, ledgerPath);
    return { plan, ...initialized };
  });
}

async function boundState(planPath, ledgerPath) {
  const plan = await loadPlan(planPath);
  let events;
  try {
    events = await readLedger(ledgerPath);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    await initializeLedger({ planPath, ledgerPath });
    events = await readLedger(ledgerPath);
  }
  validateLedgerBinding(events, plan);
  return { plan, events };
}

async function withMutation(planPath, ledgerPath, operation) {
  const plan = await loadPlan(planPath);
  return withLedgerLock(ledgerPath, async () => {
    const { events } = await initializeEvents(plan, ledgerPath);
    validateLedgerBinding(events, plan);
    requireMutable(events);
    return operation(plan, events);
  });
}

function checkMap(plan) {
  let value = CHECK_MAP_CACHE.get(plan);
  if (!value) {
    value = new Map(plan.checks.map(check => [check.check_id, check]));
    CHECK_MAP_CACHE.set(plan, value);
  }
  return value;
}

function requireRequiredCheck(plan, checkId) {
  const check = checkMap(plan).get(checkId);
  if (!check) throw new Error(`Unknown coverage check_id: ${checkId}`);
  if (check.applicability !== "REQUIRED") throw new Error(`Only REQUIRED checks can be executed: ${checkId}`);
  return check;
}

function decodeCursor(cursor) {
  if (cursor == null || cursor === "") return 0;
  const match = /^offset:(\d+)$/.exec(cursor);
  if (!match) throw new Error("Invalid cursor; use the next_cursor returned by this service");
  return Number(match[1]);
}

function page(items, cursor, limit, maxLimit) {
  const offset = decodeCursor(cursor);
  if (offset > items.length) throw new Error("Cursor is beyond the available result set");
  const size = Math.max(1, Math.min(maxLimit, limit));
  const values = items.slice(offset, offset + size);
  const nextOffset = offset + values.length;
  return {
    values,
    total: items.length,
    next_cursor: nextOffset < items.length ? `offset:${nextOffset}` : null,
  };
}

function validateSessionId(value) {
  if (!/^[a-z0-9][a-z0-9._:-]{2,255}$/i.test(value ?? "")) throw new Error(`Invalid session_id: ${value}`);
}

function validateAgent(check, agentName) {
  const expected = DOMAIN_AGENTS[check.domain];
  if (agentName !== expected) throw new Error(`Agent is not authorized for ${check.domain}: ${agentName ?? "missing"}; expected ${expected}`);
}

function assignmentTokenDigest(token) {
  if (typeof token !== "string" || token.length < 32) throw new Error("A server-issued assignment_token is required");
  return sha256(token);
}

function assignmentToken(secret, values) {
  return createHmac("sha256", secret).update(values.join("\n")).digest("base64url");
}

function requireAssignment(events, check, sessionId, token) {
  const tokenDigest = assignmentTokenDigest(token);
  const event = events.find(candidate => ["INSPECT", "DELEGATE"].includes(candidate.event_type)
    && candidate.check_id === check.check_id
    && candidate.assignment_token_sha256 === tokenDigest);
  if (!event) throw new Error("Assignment token is missing, stale, or belongs to another check");
  if (event.authorized_session_id !== sessionId) throw new Error("Assignment token is not authorized for this session; use explicit delegation");
  return event;
}

export function deriveLedgerState(plan, events) {
  const cacheKey = `${plan.manifest_digest}:${events.at(-1)?.event_hash ?? "empty"}`;
  const cached = STATE_CACHE.get(cacheKey);
  if (cached) return cached;
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
    if (event.event_type === "INSPECT" && current.execution_state !== "VERIFIED") current.execution_state = "INSPECTED";
    if (event.event_type === "RECEIPT") {
      if (current.execution_state !== "VERIFIED") current.execution_state = "INSPECTED";
      current.receipt_ids.push(event.receipt_id);
    }
    if (event.event_type === "DECISION") {
      current.execution_state = event.execution_state;
      current.result_state = event.result_state;
      current.finding_ids = event.finding_ids ?? [];
      current.decision_sequence = event.sequence;
    }
  }
  cacheSet(STATE_CACHE, cacheKey, state, LEDGER_CACHE_LIMIT);
  return state;
}

function requireUnverified(plan, events, checkId) {
  if (deriveLedgerState(plan, events).get(checkId)?.execution_state === "VERIFIED") {
    throw new Error(`VERIFIED decision is immutable: ${checkId}`);
  }
}

async function preflightAssignment(planPath, ledgerPath, checkId, sessionId, token) {
  const { plan, events } = await boundState(planPath, ledgerPath);
  const check = requireRequiredCheck(plan, checkId);
  requireUnverified(plan, events, checkId);
  requireAssignment(events, check, sessionId, token);
}

export async function inspectSubject({ planPath, ledgerPath, checkId, sessionId, agentName, idempotencyKey }) {
  validateSessionId(sessionId);
  return withMutation(planPath, ledgerPath, async (plan, events) => {
    const check = requireRequiredCheck(plan, checkId);
    validateAgent(check, agentName);
    requireUnverified(plan, events, checkId);
    const secret = await ledgerSecret(ledgerPath);
    const token = assignmentToken(secret, [plan.manifest_digest, checkId, sessionId, agentName, idempotencyKey]);
    const body = {
      audit_id: plan.audit_id,
      plan_digest: plan.manifest_digest,
      check_id: checkId,
      focus_area_id: check.focus_area_id,
      agent_name: agentName,
      authorized_session_id: sessionId,
      idempotency_key: idempotencyKey,
      assignment_id: `assignment:${sha256([plan.manifest_digest, checkId, agentName, sessionId, idempotencyKey].join("\n")).slice(0, 32)}`,
      assignment_token_sha256: assignmentTokenDigest(token),
    };
    const prior = findIdempotent(events, "INSPECT", body);
    const event = prior ?? await appendEvent(ledgerPath, events, "INSPECT", body);
    return { check, event, assignment_token: token, idempotent_replay: Boolean(prior) };
  });
}

export async function delegateAssignment({
  planPath,
  ledgerPath,
  checkId,
  sessionId,
  assignmentToken: currentToken,
  targetSessionId,
  idempotencyKey,
}) {
  validateSessionId(sessionId);
  validateSessionId(targetSessionId);
  return withMutation(planPath, ledgerPath, async (plan, events) => {
    const check = requireRequiredCheck(plan, checkId);
    requireUnverified(plan, events, checkId);
    const current = requireAssignment(events, check, sessionId, currentToken);
    const secret = await ledgerSecret(ledgerPath);
    const token = assignmentToken(secret, [
      plan.manifest_digest,
      current.assignment_id,
      current.assignment_token_sha256,
      targetSessionId,
      idempotencyKey,
    ]);
    const body = {
      audit_id: plan.audit_id,
      plan_digest: plan.manifest_digest,
      check_id: checkId,
      focus_area_id: check.focus_area_id,
      agent_name: current.agent_name,
      authorized_session_id: targetSessionId,
      delegated_by_session_id: sessionId,
      parent_assignment_token_sha256: current.assignment_token_sha256,
      assignment_id: current.assignment_id,
      assignment_token_sha256: assignmentTokenDigest(token),
      idempotency_key: idempotencyKey,
    };
    const prior = findIdempotent(events, "DELEGATE", body);
    const event = prior ?? await appendEvent(ledgerPath, events, "DELEGATE", body);
    return { delegation: event, assignment_token: token, idempotent_replay: Boolean(prior) };
  });
}

function sourceHashesForIds(plan, sourceFileIds) {
  if (!Array.isArray(sourceFileIds) || sourceFileIds.length === 0) throw new Error("source_file_ids must be a non-empty array");
  const sourceIndex = new Map((plan.source_index ?? []).map(source => [source.file_id, source]));
  return sourceFileIds.map(fileId => {
    const source = sourceIndex.get(fileId);
    if (!source) throw new Error(`Stale or non-frozen source file_id: ${fileId}`);
    return {
      file_id: source.file_id,
      sha256: source.sha256,
      ...(source.sha256 === null ? { link_target: source.link_target } : {}),
    };
  });
}

function requiredSourceSet(plan, check) {
  const frozenHashes = sourceHashesForIds(plan, sourceFileIdsForCheck(plan, check));
  return {
    mode: "required-source-set",
    source_set_id: check.required_source_set_id,
    source_count: frozenHashes.length,
    source_set_sha256: sha256(JSON.stringify(frozenHashes)),
  };
}

function matchesRequiredSourceSet(sourceEvidence, expected) {
  return sourceEvidence?.mode === expected.mode
    && sourceEvidence.source_set_id === expected.source_set_id
    && sourceEvidence.source_count === expected.source_count
    && sourceEvidence.source_set_sha256 === expected.source_set_sha256;
}

function validateLocators(locators, check) {
  if (!Array.isArray(locators) || locators.length === 0) throw new Error("locators must be a non-empty typed object array");
  for (const locator of locators) {
    if (!locator || typeof locator !== "object" || Array.isArray(locator) || typeof locator.kind !== "string") {
      throw new Error("Each locator requires a typed kind");
    }
    if (locator.kind === "required-source-set") {
      if (locator.check_id !== check.check_id || locator.source_set_id !== check.required_source_set_id
        || locator.source_count !== check.required_source_count) {
        throw new Error("required-source-set locator is not bound to the frozen check");
      }
      continue;
    }
    if (["source-location", "query-match"].includes(locator.kind)) {
      if (typeof locator.path !== "string" || locator.path.trim() === ""
        || !Number.isInteger(locator.line_start) || locator.line_start < 1) {
        throw new Error(`${locator.kind} locator requires path and line_start`);
      }
      continue;
    }
    if (locator.kind === "function-location") {
      if (typeof locator.function_id !== "string" || typeof locator.path !== "string"
        || !Number.isInteger(locator.line_start) || locator.line_start < 1) {
        throw new Error("function-location locator requires function_id, path, and line_start");
      }
      continue;
    }
    if (locator.kind === "artifact-location") {
      if (typeof locator.path !== "string" || !/^[a-f0-9]{64}$/.test(locator.sha256 ?? "")) {
        throw new Error("artifact-location locator requires path and sha256");
      }
      continue;
    }
    throw new Error(`Unsupported locator kind: ${locator.kind}`);
  }
}

async function hashFile(path) {
  const absolute = resolve(path);
  const metadata = await stat(absolute);
  if (!metadata.isFile()) throw new Error(`Result artifact is not a regular file: ${absolute}`);
  if (metadata.size > MAX_RESULT_ARTIFACT_BYTES) {
    throw new Error(`Result artifact exceeds ${MAX_RESULT_ARTIFACT_BYTES} bytes: ${absolute}`);
  }
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(absolute)) hash.update(chunk);
  return { path: absolute, bytes: metadata.size, sha256: hash.digest("hex") };
}

async function attestResult({ resultPayload, resultArtifactPath, expectedResultDigest }) {
  const values = [resultPayload, resultArtifactPath].filter(value => value !== undefined);
  if (values.length !== 1) throw new Error("Provide exactly one of result_payload or result_artifact_path");
  let attestation;
  if (resultPayload !== undefined) {
    if (typeof resultPayload !== "string") throw new Error("result_payload must be a string");
    if (Buffer.byteLength(resultPayload) > MAX_INLINE_RESULT_BYTES) {
      throw new Error(`result_payload exceeds ${MAX_INLINE_RESULT_BYTES} bytes`);
    }
    attestation = {
      mode: "server-hashed-inline",
      bytes: Buffer.byteLength(resultPayload),
      sha256: sha256(resultPayload),
    };
  } else {
    attestation = { mode: "server-hashed-artifact", ...await hashFile(resultArtifactPath) };
  }
  if (expectedResultDigest !== undefined && expectedResultDigest !== attestation.sha256) {
    throw new Error("Client result_digest does not match the server-derived result attestation");
  }
  return attestation;
}

export async function recordToolResult({
  planPath,
  ledgerPath,
  checkId,
  sessionId,
  assignmentToken,
  idempotencyKey,
  sourceScope,
  locators,
  queryOrRule,
  tool,
  toolVersion,
  resultPayload,
  resultArtifactPath,
  resultDigest,
  resultSummary,
}) {
  validateSessionId(sessionId);
  if (resultArtifactPath !== undefined) {
    await preflightAssignment(planPath, ledgerPath, checkId, sessionId, assignmentToken);
  }
  const resultAttestation = await attestResult({
    resultPayload,
    resultArtifactPath,
    expectedResultDigest: resultDigest,
  });
  return withMutation(planPath, ledgerPath, async (plan, events) => {
    const check = requireRequiredCheck(plan, checkId);
    requireUnverified(plan, events, checkId);
    const assignment = requireAssignment(events, check, sessionId, assignmentToken);
    if (sourceScope !== "required") throw new Error("Coverage v3 receipts require source_scope=required");
    const sourceEvidence = requiredSourceSet(plan, check);
    validateLocators(locators, check);
    if (typeof queryOrRule !== "string" || queryOrRule.trim() === "") throw new Error("query_or_rule is required");
    if (typeof tool !== "string" || tool.trim() === "") throw new Error("tool is required");
    if (typeof toolVersion !== "string" || toolVersion.trim() === "") throw new Error("tool_version is required");
    const receiptId = `receipt:${sha256([plan.manifest_digest, checkId, assignment.assignment_id, idempotencyKey].join("\n")).slice(0, 32)}`;
    const body = {
      audit_id: plan.audit_id,
      plan_digest: plan.manifest_digest,
      check_id: checkId,
      session_id: sessionId,
      assignment_id: assignment.assignment_id,
      idempotency_key: idempotencyKey,
      receipt_id: receiptId,
      source_set: sourceEvidence,
      locators,
      query_or_rule: queryOrRule,
      tool,
      tool_version: toolVersion,
      result_attestation: resultAttestation,
      result_digest: resultAttestation.sha256,
      result_summary: resultSummary ?? null,
    };
    const prior = findIdempotent(events, "RECEIPT", body);
    const event = prior ?? await appendEvent(ledgerPath, events, "RECEIPT", body);
    return { receipt: event, idempotent_replay: Boolean(prior) };
  });
}

function findingBinding(plan, check) {
  return {
    plan_digest: plan.manifest_digest,
    scope_digest: plan.scope_digest,
    check_id: check.check_id,
    focus_area_id: check.focus_area_id,
    domain: check.domain,
    vulnerability_type_id: check.vulnerability_type_id,
    lens: check.lens,
    dimensions: check.dimensions,
  };
}

async function attestFindingArtifacts(findingIds, findingArtifacts, { plan, check }) {
  if (new Set(findingIds).size !== findingIds.length) throw new Error("finding_ids must be unique");
  if (findingIds.length !== findingArtifacts.length) throw new Error("Each finding_id requires exactly one finding artifact");
  const binding = findingBinding(plan, check);
  const byId = new Map();
  for (const item of findingArtifacts) {
    if (!item || typeof item.finding_id !== "string" || typeof item.path !== "string" || byId.has(item.finding_id)) {
      throw new Error("finding_artifacts requires unique finding_id/path rows");
    }
    const absolute = resolve(item.path);
    const metadata = await stat(absolute);
    if (!metadata.isFile()) throw new Error(`Finding artifact is not a regular file: ${absolute}`);
    if (metadata.size > MAX_FINDING_ARTIFACT_BYTES) {
      throw new Error(`Finding artifact exceeds ${MAX_FINDING_ARTIFACT_BYTES} bytes: ${absolute}`);
    }
    const bytes = await readFile(absolute);
    const { finding_object_digest: findingObjectDigest } = parseFindingArtifact(bytes, {
      expectedFindingId: item.finding_id,
      auditId: plan.audit_id,
      scopeDigest: plan.scope_digest,
      check,
    });
    byId.set(item.finding_id, {
      finding_id: item.finding_id,
      path: absolute,
      bytes: bytes.length,
      sha256: sha256(bytes),
      finding_object_digest: findingObjectDigest,
      binding,
    });
  }
  for (const id of findingIds) if (!byId.has(id)) throw new Error(`Missing finding artifact: ${id}`);
  for (const id of byId.keys()) if (!findingIds.includes(id)) throw new Error(`Unexpected finding artifact: ${id}`);
  return findingIds.map(id => byId.get(id));
}

async function findingArtifactIssues(events) {
  const issues = [];
  for (const event of events.filter(candidate => candidate.event_type === "DECISION" && candidate.result_state === "FINDING")) {
    const rows = event.finding_artifacts ?? [];
    if (rows.length !== (event.finding_ids?.length ?? 0)) {
      issues.push({ code: "FINDING_ARTIFACT_SET_MISMATCH", sequence: event.sequence, check_id: event.check_id });
      continue;
    }
    for (const findingId of event.finding_ids ?? []) {
      const row = rows.find(candidate => candidate.finding_id === findingId);
      if (!row) {
        issues.push({ code: "FINDING_ARTIFACT_MISSING", sequence: event.sequence, check_id: event.check_id, finding_id: findingId });
        continue;
      }
      try {
        const metadata = await stat(row.path);
        if (!metadata.isFile() || metadata.size !== row.bytes || metadata.size > MAX_FINDING_ARTIFACT_BYTES) {
          throw new Error("size or file type changed");
        }
        const bytes = await readFile(row.path);
        if (sha256(bytes) !== row.sha256) throw new Error("artifact digest changed");
        if (!row.binding || row.binding.plan_digest !== event.plan_digest || row.binding.check_id !== event.check_id) {
          throw new Error("finding binding is missing or event-mismatched");
        }
        const { finding_object_digest: findingObjectDigest } = parseFindingArtifact(bytes, {
          expectedFindingId: findingId,
          auditId: event.audit_id,
          scopeDigest: row.binding.scope_digest,
          check: row.binding,
        });
        if (findingObjectDigest !== row.finding_object_digest) throw new Error("finding object digest changed");
      } catch (error) {
        issues.push({
          code: "FINDING_ARTIFACT_INVALID",
          sequence: event.sequence,
          check_id: event.check_id,
          finding_id: findingId,
          path: row.path,
          reason: error.message,
        });
      }
    }
  }
  return issues;
}

export async function submitDecision({
  planPath,
  ledgerPath,
  checkId,
  sessionId,
  assignmentToken,
  idempotencyKey,
  executionState,
  resultState,
  receiptIds = [],
  findingIds = [],
  findingArtifacts = [],
  rationale,
}) {
  validateSessionId(sessionId);
  if (!["VERIFIED", "GAP", "INVALIDATED"].includes(executionState)) throw new Error("Decision execution_state must be VERIFIED, GAP, or INVALIDATED; N/A is planner-only");
  if (!["NO_FINDING", "FINDING", "INCONCLUSIVE"].includes(resultState)) throw new Error("Invalid decision result_state");
  if (executionState === "VERIFIED" && resultState === "INCONCLUSIVE") throw new Error("VERIFIED cannot be INCONCLUSIVE");
  if (executionState !== "VERIFIED" && resultState !== "INCONCLUSIVE") throw new Error("GAP/INVALIDATED decisions must be INCONCLUSIVE");
  if (resultState === "FINDING" && findingIds.length === 0) throw new Error("FINDING requires finding_ids");
  if (resultState !== "FINDING" && (findingIds.length > 0 || findingArtifacts.length > 0)) throw new Error("Finding evidence is only valid for FINDING");
  if (new Set(receiptIds).size !== receiptIds.length) throw new Error("receipt_ids must be unique");
  if (resultState === "FINDING") {
    await preflightAssignment(planPath, ledgerPath, checkId, sessionId, assignmentToken);
  }
  return withMutation(planPath, ledgerPath, async (plan, events) => {
    const check = requireRequiredCheck(plan, checkId);
    const assignment = requireAssignment(events, check, sessionId, assignmentToken);
    const attestedFindings = resultState === "FINDING"
      ? await attestFindingArtifacts(findingIds, findingArtifacts, { plan, check })
      : [];
    const receiptEvents = events.filter(event => event.event_type === "RECEIPT"
      && event.check_id === checkId && event.assignment_id === assignment.assignment_id);
    const validReceipts = new Set(receiptEvents.map(event => event.receipt_id));
    if (executionState === "VERIFIED") {
      if (!Array.isArray(receiptIds) || receiptIds.length === 0) throw new Error("VERIFIED requires at least one receipt_id");
      for (const receiptId of receiptIds) if (!validReceipts.has(receiptId)) throw new Error(`Receipt is missing, stale, unauthorized, or belongs to another check: ${receiptId}`);
      const expectedSourceSet = requiredSourceSet(plan, check);
      if (!receiptEvents.filter(event => receiptIds.includes(event.receipt_id))
        .some(event => matchesRequiredSourceSet(event.source_set, expectedSourceSet))) {
        throw new Error("VERIFIED receipts do not cover the frozen required source set");
      }
    }
    if (typeof rationale !== "string" || rationale.trim() === "") throw new Error("Decision rationale is required");
    const body = {
      audit_id: plan.audit_id,
      plan_digest: plan.manifest_digest,
      check_id: checkId,
      session_id: sessionId,
      assignment_id: assignment.assignment_id,
      idempotency_key: idempotencyKey,
      execution_state: executionState,
      result_state: resultState,
      receipt_ids: receiptIds,
      finding_ids: findingIds,
      finding_artifacts: attestedFindings,
      rationale,
    };
    const prior = findIdempotent(events, "DECISION", body);
    const latestState = deriveLedgerState(plan, events).get(checkId);
    if (!prior && latestState?.execution_state === "VERIFIED") {
      throw new Error(`VERIFIED decision is immutable; submit follow-up evidence under a different unresolved check: ${checkId}`);
    }
    const event = prior ?? await appendEvent(ledgerPath, events, "DECISION", body);
    return { decision: event, idempotent_replay: Boolean(prior) };
  });
}

export async function getPackets({ planPath, ledgerPath, focusAreaId, domain, lens, subjectKind, cursor, limit = 25 }) {
  const { plan, events } = await boundState(planPath, ledgerPath);
  const state = deriveLedgerState(plan, events);
  const matching = [...state.values()]
    .filter(item => !focusAreaId || item.check.focus_area_id === focusAreaId)
    .filter(item => !domain || item.check.domain === domain)
    .filter(item => !lens || item.check.lens === lens)
    .filter(item => !subjectKind || item.check.subject_kind === subjectKind)
    .filter(item => item.execution_state !== "VERIFIED")
    .sort((left, right) => left.check.check_id.localeCompare(right.check.check_id));
  const result = page(matching, cursor, limit, 250);
  return {
    audit_id: plan.audit_id,
    plan_digest: plan.manifest_digest,
    total: result.total,
    next_cursor: result.next_cursor,
    packets: result.values,
  };
}

export async function getGaps({ planPath, ledgerPath, cursor, limit = 25 }) {
  const { plan, events } = await boundState(planPath, ledgerPath);
  const state = deriveLedgerState(plan, events);
  const allGaps = [...state.values()]
    .filter(item => item.execution_state !== "VERIFIED")
    .sort((left, right) => left.check.check_id.localeCompare(right.check.check_id));
  const result = page(allGaps, cursor, limit, 250);
  return {
    audit_id: plan.audit_id,
    required: state.size,
    verified: state.size - allGaps.length,
    total_gaps: allGaps.length,
    next_cursor: result.next_cursor,
    gaps: result.values,
  };
}

export async function getSubjectSources({ planPath, ledgerPath, checkId, cursor, limit = 25 }) {
  const { plan } = await boundState(planPath, ledgerPath);
  const check = requireRequiredCheck(plan, checkId);
  const sourceIndex = new Map((plan.source_index ?? []).map(source => [source.file_id, source]));
  const sources = sourceFileIdsForCheck(plan, check).map(fileId => {
    const source = sourceIndex.get(fileId);
    if (!source) throw new Error(`Coverage check references an unknown frozen source: ${fileId}`);
    return source;
  });
  const result = page(sources, cursor, limit, 100);
  return {
    audit_id: plan.audit_id,
    plan_digest: plan.manifest_digest,
    check_id: check.check_id,
    total_sources: result.total,
    next_cursor: result.next_cursor,
    sources: result.values,
  };
}

function ledgerCounts(plan, events) {
  const state = deriveLedgerState(plan, events);
  return {
    state,
    required: state.size,
    verified: [...state.values()].filter(item => item.execution_state === "VERIFIED").length,
    findings: [...state.values()].filter(item => item.result_state === "FINDING").length,
  };
}

export async function checkpointLedger({ planPath, ledgerPath, idempotencyKey, label = "partial" }) {
  return withMutation(planPath, ledgerPath, async (plan, events) => {
    const counts = ledgerCounts(plan, events);
    const body = {
      audit_id: plan.audit_id,
      plan_digest: plan.manifest_digest,
      idempotency_key: idempotencyKey,
      label,
      seal_state: "PARTIAL_CHECKPOINT",
      required: counts.required,
      verified: counts.verified,
      unknown: plan.summary.unknown,
      inventory_bounded: plan.inventory.bounded,
      inventory_gap_files: plan.inventory.gap_files,
      candidate_interfaces: plan.inventory.candidate_interfaces,
      chain_head_before_checkpoint: events.at(-1).event_hash,
    };
    const prior = findIdempotent(events, "PARTIAL_CHECKPOINT", body);
    const event = prior ?? await appendEvent(ledgerPath, events, "PARTIAL_CHECKPOINT", body);
    return { checkpoint: event, idempotent_replay: Boolean(prior) };
  });
}

export async function finalizeLedger({ planPath, ledgerPath, idempotencyKey }) {
  const plan = await loadPlan(planPath);
  return withLedgerLock(ledgerPath, async () => {
    const { events } = await initializeEvents(plan, ledgerPath);
    const prior = events.find(event => event.event_type === "FINALIZE_COMPLETE");
    const findingIssues = await findingArtifactIssues(events);
    if (findingIssues.length > 0) {
      throw new Error(`Finding artifact verification failed: ${findingIssues.map(issue => `${issue.finding_id ?? issue.check_id}:${issue.reason ?? issue.code}`).join(", ")}`);
    }
    if (prior) {
      if (prior.idempotency_key !== idempotencyKey) throw new Error("Coverage ledger is already finalized");
      return { finalization: prior, idempotent_replay: true };
    }
    if (plan.summary.unknown > 0 || !plan.complete || !plan.inventory.bounded) {
      throw new Error("Coverage plan contains UNKNOWN applicability or unbounded inventory and cannot be finalized");
    }
    const counts = ledgerCounts(plan, events);
    if (counts.verified !== counts.required) throw new Error(`Coverage ledger has ${counts.required - counts.verified} unverified REQUIRED checks`);
    const body = {
      audit_id: plan.audit_id,
      plan_digest: plan.manifest_digest,
      idempotency_key: idempotencyKey,
      seal_state: "FINALIZED_COMPLETE",
      required: counts.required,
      verified: counts.verified,
      findings: counts.findings,
      chain_head_before_finalize: events.at(-1).event_hash,
    };
    const event = await appendEvent(ledgerPath, events, "FINALIZE_COMPLETE", body);
    return { finalization: event, idempotent_replay: false };
  });
}

export async function finalizePartialLedger({ planPath, ledgerPath, idempotencyKey, terminationReason }) {
  if (!new Set(["budget-exhausted", "round-limit-reached", "operator-stop"]).has(terminationReason)) {
    throw new Error("termination_reason must be budget-exhausted, round-limit-reached, or operator-stop");
  }
  const plan = await loadPlan(planPath);
  return withLedgerLock(ledgerPath, async () => {
    const { events } = await initializeEvents(plan, ledgerPath);
    const terminal = events.find(event => ["FINALIZE_COMPLETE", "FINALIZE_PARTIAL"].includes(event.event_type));
    if (terminal) {
      const body = {
        audit_id: plan.audit_id,
        plan_digest: plan.manifest_digest,
        idempotency_key: idempotencyKey,
        termination_reason: terminationReason,
        seal_state: "FINALIZED_PARTIAL",
      };
      const prior = findIdempotent(events, "FINALIZE_PARTIAL", body);
      if (prior) return { finalization: prior, idempotent_replay: true };
      throw new Error("Coverage ledger is already finalized");
    }
    const findingIssues = await findingArtifactIssues(events);
    if (findingIssues.length > 0) {
      throw new Error(`Finding artifact verification failed: ${findingIssues.map(issue => `${issue.finding_id ?? issue.check_id}:${issue.reason ?? issue.code}`).join(", ")}`);
    }
    const counts = ledgerCounts(plan, events);
    const body = {
      audit_id: plan.audit_id,
      plan_digest: plan.manifest_digest,
      idempotency_key: idempotencyKey,
      termination_reason: terminationReason,
      seal_state: "FINALIZED_PARTIAL",
      required: counts.required,
      verified: counts.verified,
      findings: counts.findings,
      unknown: plan.summary.unknown,
      inventory_bounded: plan.inventory.bounded,
      inventory_gap_files: plan.inventory.gap_files,
      candidate_interfaces: plan.inventory.candidate_interfaces,
      chain_head_before_terminal: events.at(-1).event_hash,
    };
    const event = await appendEvent(ledgerPath, events, "FINALIZE_PARTIAL", body);
    return { finalization: event, idempotent_replay: false };
  });
}

export async function verifyLedger({ planPath, ledgerPath, requireFinalized = true }) {
  const plan = await loadPlan(planPath);
  const events = await readLedger(ledgerPath);
  validateLedgerBinding(events, plan);
  const state = deriveLedgerState(plan, events);
  const completeFinalization = events.find(event => event.event_type === "FINALIZE_COMPLETE") ?? null;
  const partialFinalization = events.find(event => event.event_type === "FINALIZE_PARTIAL") ?? null;
  const finalization = completeFinalization ?? partialFinalization;
  const checkpoint = [...events].reverse().find(event => event.event_type === "PARTIAL_CHECKPOINT") ?? null;
  const gaps = [...state.values()].filter(item => item.execution_state !== "VERIFIED");
  const issues = await findingArtifactIssues(events);
  if (plan.summary.unknown > 0) issues.push({ code: "UNKNOWN_APPLICABILITY", count: plan.summary.unknown });
  if (!plan.inventory.bounded) {
    issues.push({
      code: "UNBOUNDED_INTERFACE_INVENTORY",
      gap_files: plan.inventory.gap_files,
      candidate_interfaces: plan.inventory.candidate_interfaces,
      unresolved_interfaces: plan.inventory.unresolved_interfaces,
    });
  }
  if (gaps.length > 0) issues.push({ code: "UNVERIFIED_REQUIRED_CHECKS", count: gaps.length });
  if (requireFinalized && !completeFinalization) issues.push({ code: "LEDGER_NOT_FINALIZED_COMPLETE" });
  if (completeFinalization && completeFinalization.chain_head_before_finalize !== events.at(-2)?.event_hash) issues.push({ code: "FINALIZATION_CHAIN_HEAD_MISMATCH" });
  if (partialFinalization && partialFinalization.chain_head_before_terminal !== events.at(-2)?.event_hash) issues.push({ code: "FINALIZATION_CHAIN_HEAD_MISMATCH" });
  if (finalization && events.at(-1) !== finalization) issues.push({ code: "EVENT_AFTER_FINALIZATION" });
  return {
    plan,
    events,
    state,
    finalization,
    checkpoint,
    seal_state: completeFinalization ? "FINALIZED_COMPLETE" : partialFinalization ? "FINALIZED_PARTIAL" : checkpoint ? "PARTIAL_CHECKPOINT" : "OPEN",
    gaps,
    issues,
    complete: issues.length === 0,
  };
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
