import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

export const AUDIT_TODO_SCHEMA_VERSION = 1;
export const AUDIT_TODO_STATES = Object.freeze(["PENDING", "RUNNING", "DONE", "GAP", "FAILED"]);
const TERMINAL_ITEM_STATES = new Set(["DONE", "GAP", "FAILED"]);
const DEFAULT_LEASE_MINUTES = 30;
const DEFAULT_MAX_ATTEMPTS = 3;
const LEGACY_COVERAGE_UNIT_ITEM = /^(?:todo:)?coverage-unit:/;

function now() {
  return new Date().toISOString();
}

function object(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function positiveInteger(value, fallback, maximum = 10_000) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > maximum) return fallback;
  return parsed;
}

function safeChild(root, candidate) {
  const value = relative(resolve(root), resolve(candidate));
  return value !== "" && value !== ".." && !value.startsWith(`..${sep}`) && !isAbsolute(value);
}

function itemFromUnit(unit, index) {
  if (!object(unit) || typeof unit.unit_id !== "string" || !unit.unit_id) {
    throw new Error(`覆盖计划中的第 ${index + 1} 个 coverage unit 缺少 unit_id。`);
  }
  if (typeof unit.focus_area_id !== "string" || !unit.focus_area_id) {
    throw new Error(`coverage unit ${unit.unit_id} 缺少 focus_area_id。`);
  }
  if (typeof unit.domain !== "string" || !unit.domain) {
    throw new Error(`coverage unit ${unit.unit_id} 缺少 domain。`);
  }
  if (typeof unit.agent_name !== "string" || !unit.agent_name) {
    throw new Error(`coverage unit ${unit.unit_id} 缺少 agent_name。`);
  }
  return {
    item_id: `todo:${unit.unit_id}`,
    focus_area_id: unit.focus_area_id,
    domain: unit.domain,
    agent_name: unit.agent_name,
    assignment_id: typeof unit.assignment_id === "string" ? unit.assignment_id : unit.unit_id,
    required_lenses: Array.isArray(unit.required_lenses) ? unit.required_lenses.filter(value => typeof value === "string") : [],
    source_set_id: typeof unit.required_source_set_id === "string" ? unit.required_source_set_id : null,
    expected_check_count: Array.isArray(unit.check_ids) ? unit.check_ids.length : Number(unit.required_check_count ?? 0),
    status: "PENDING",
    packet_id: null,
    attempt_count: 0,
    lease_expires_at: null,
    artifact_path: null,
    finding_ids: [],
    gap_reason: null,
    updated_at: now(),
  };
}

function validateTodo(todo) {
  const errors = [];
  if (!object(todo)) return ["todo-not-object"];
  if (todo.schema_version !== AUDIT_TODO_SCHEMA_VERSION) errors.push("todo-schema-version-invalid");
  if (typeof todo.audit_id !== "string" || !todo.audit_id) errors.push("todo-audit-id-invalid");
  if (!Array.isArray(todo.items)) errors.push("todo-items-invalid");
  if (!Array.isArray(todo.packets)) errors.push("todo-packets-invalid");
  const itemIds = new Set();
  for (const item of Array.isArray(todo.items) ? todo.items : []) {
    if (!object(item) || typeof item.item_id !== "string" || !item.item_id) {
      errors.push("todo-item-id-invalid");
      continue;
    }
    if (itemIds.has(item.item_id)) errors.push(`todo-item-duplicate:${item.item_id}`);
    itemIds.add(item.item_id);
    if (!AUDIT_TODO_STATES.includes(item.status)) errors.push(`todo-item-state-invalid:${item.item_id}`);
  }
  return [...new Set(errors)];
}

function migratedLegacyStatus(value) {
  const status = typeof value === "string" ? value.trim().toUpperCase() : "";
  if (AUDIT_TODO_STATES.includes(status)) return status;
  if (["DONE", "COMPLETE", "COMPLETED", "VERIFIED"].includes(status)) return "DONE";
  if (["GAP", "PARTIAL", "INCONCLUSIVE", "INVALIDATED", "SKIPPED"].includes(status)) return "GAP";
  if (["FAILED", "ERROR", "CANCELLED", "CANCELED"].includes(status)) return "FAILED";
  // There is no packet/lease equivalence in the retired Coverage Ledger
  // workflow. Requeue active or unknown work rather than claiming it finished.
  return "PENDING";
}

function migrateLegacyCoverageTodo(todo, errors) {
  const items = Array.isArray(todo?.items) ? todo.items : [];
  const legacyItems = items.filter(item => object(item) && LEGACY_COVERAGE_UNIT_ITEM.test(item.item_id));
  if (legacyItems.length === 0) return null;
  if (!errors.every(error => /^todo-item-state-invalid:(?:todo:)?coverage-unit:/.test(error))) return null;
  const migratedAt = now();
  const migratedItems = items.map(item => {
    if (!object(item) || !LEGACY_COVERAGE_UNIT_ITEM.test(item.item_id)) return item;
    const status = migratedLegacyStatus(item.status);
    return {
      ...item,
      item_id: item.item_id.startsWith("todo:") ? item.item_id : `todo:${item.item_id}`,
      focus_area_id: typeof item.focus_area_id === "string" && item.focus_area_id ? item.focus_area_id : "legacy-coverage",
      domain: typeof item.domain === "string" && item.domain ? item.domain : "legacy",
      agent_name: typeof item.agent_name === "string" && item.agent_name ? item.agent_name : "security-audit-orchestrator",
      assignment_id: typeof item.assignment_id === "string" && item.assignment_id ? item.assignment_id : item.item_id,
      required_lenses: Array.isArray(item.required_lenses) ? item.required_lenses.filter(value => typeof value === "string") : [],
      source_set_id: typeof item.source_set_id === "string" ? item.source_set_id : null,
      expected_check_count: Number.isFinite(Number(item.expected_check_count)) ? Math.max(0, Number(item.expected_check_count)) : 0,
      status,
      // Old Coverage Ledger assignments cannot be resumed as local packets.
      // Resetting them makes the current scheduler claim only unfinished work.
      packet_id: null,
      lease_expires_at: null,
      attempt_count: Number.isInteger(item.attempt_count) && item.attempt_count >= 0 ? item.attempt_count : 0,
      artifact_path: typeof item.artifact_path === "string" ? item.artifact_path : null,
      finding_ids: Array.isArray(item.finding_ids) ? item.finding_ids.filter(value => typeof value === "string").slice(0, 500) : [],
      gap_reason: status === "GAP"
        ? (typeof item.gap_reason === "string" && item.gap_reason.trim() ? item.gap_reason.trim().slice(0, 4000) : `旧 Coverage Ledger 状态 ${String(item.status ?? "unknown")} 已迁移为 GAP。`)
        : null,
      legacy_coverage_status: typeof item.status === "string" ? item.status : null,
      updated_at: migratedAt,
    };
  });
  return {
    ...todo,
    items: migratedItems,
    // Legacy packet metadata refers to retired assignment tokens and must not
    // be used to resume work under the local scheduler.
    packets: [],
    updated_at: migratedAt,
    legacy_migration: {
      kind: "coverage-ledger-local-todo",
      migrated_at: migratedAt,
      migrated_item_count: legacyItems.length,
    },
  };
}

async function writeTodo(todoPath, todo) {
  const path = resolve(todoPath);
  const errors = validateTodo(todo);
  if (errors.length > 0) throw new Error(`本地审计任务清单无效：${errors.join(", ")}`);
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(todo, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporary, path);
}

export async function readAuditTodo(todoPath, { allowMissing = false } = {}) {
  try {
    const path = resolve(todoPath);
    const source = await readFile(path, "utf8");
    const todo = JSON.parse(source);
    const errors = validateTodo(todo);
    const migrated = errors.length > 0 ? migrateLegacyCoverageTodo(todo, errors) : null;
    if (migrated) {
      const backup = `${path}.legacy-coverage-ledger.${Date.now()}.${randomUUID()}.json`;
      await writeFile(backup, source, { encoding: "utf8", mode: 0o600, flag: "wx" });
      await writeTodo(path, migrated);
      return migrated;
    }
    if (errors.length > 0) throw new Error(`本地审计任务清单无效：${errors.join(", ")}`);
    return todo;
  } catch (error) {
    if (allowMissing && error?.code === "ENOENT") return null;
    throw error;
  }
}

export function summarizeAuditTodo(todo) {
  const items = Array.isArray(todo?.items) ? todo.items : [];
  const counts = Object.fromEntries(AUDIT_TODO_STATES.map(state => [state.toLowerCase(), 0]));
  const byAgent = new Map();
  for (const item of items) {
    const state = AUDIT_TODO_STATES.includes(item.status) ? item.status : "FAILED";
    counts[state.toLowerCase()] += 1;
    const current = byAgent.get(item.agent_name) ?? { agent_name: item.agent_name, total: 0, pending: 0, running: 0, done: 0, gap: 0, failed: 0 };
    current.total += 1;
    current[state.toLowerCase()] += 1;
    byAgent.set(item.agent_name, current);
  }
  const terminal = counts.done + counts.gap + counts.failed;
  const finalizationReady = items.length > 0 && counts.pending === 0 && counts.running === 0 && counts.failed === 0;
  const nextAction = items.length === 0
    ? "INITIALIZE"
    : counts.pending > 0
      ? "CLAIM"
      : counts.running > 0
        ? "RECOVER_OR_WAIT"
        : counts.failed > 0
          ? "REPAIR_FAILURES"
          : counts.gap > 0
            ? "FINALIZE_WITH_RESIDUAL_GAPS"
            : "FINALIZE";
  return {
    audit_id: todo?.audit_id ?? null,
    total: items.length,
    pending: counts.pending,
    running: counts.running,
    done: counts.done,
    gap: counts.gap,
    failed: counts.failed,
    terminal,
    complete: finalizationReady,
    finalization_ready: finalizationReady,
    next_action: nextAction,
    progress: items.length === 0 ? 0 : Math.round((terminal / items.length) * 100),
    updated_at: todo?.updated_at ?? null,
    by_agent: [...byAgent.values()].sort((left, right) => left.agent_name.localeCompare(right.agent_name)),
  };
}

export async function initializeAuditTodo({ todoPath, auditId, planPath }) {
  if (typeof auditId !== "string" || !auditId) throw new Error("audit_id 不能为空。");
  const existing = await readAuditTodo(todoPath, { allowMissing: true });
  if (existing) {
    if (existing.audit_id !== auditId) throw new Error("本地任务清单已绑定到其他 audit_id。");
    if (existing.items.length > 0) {
      if (existing.plan_path && resolve(existing.plan_path) !== resolve(planPath)) {
        throw new Error("本地任务清单已绑定到其他 Coverage Plan，拒绝覆盖已有调度状态。");
      }
      return { todo: existing, created: false, summary: summarizeAuditTodo(existing) };
    }
  }
  const plan = JSON.parse(await readFile(resolve(planPath), "utf8"));
  if (plan.audit_id !== auditId) throw new Error("Coverage Plan 的 audit_id 与本地任务不一致。");
  const units = Array.isArray(plan.coverage_units) ? plan.coverage_units : [];
  if (units.length === 0) throw new Error("Coverage Plan 没有可调度的 coverage_units。");
  const itemIds = new Set();
  const items = units.map(itemFromUnit);
  for (const item of items) {
    if (itemIds.has(item.item_id)) throw new Error(`Coverage Plan 包含重复的调度项：${item.item_id}`);
    itemIds.add(item.item_id);
  }
  const createdAt = existing?.created_at ?? now();
  const todo = {
    schema_version: AUDIT_TODO_SCHEMA_VERSION,
    audit_id: auditId,
    plan_path: resolve(planPath),
    created_at: createdAt,
    updated_at: createdAt,
    items,
    packets: existing?.packets ?? [],
  };
  await writeTodo(todoPath, todo);
  return { todo, created: true, summary: summarizeAuditTodo(todo) };
}

export async function createEmptyAuditTodo({ todoPath, auditId }) {
  const existing = await readAuditTodo(todoPath, { allowMissing: true });
  if (existing) return { todo: existing, created: false, summary: summarizeAuditTodo(existing) };
  const createdAt = now();
  const todo = {
    schema_version: AUDIT_TODO_SCHEMA_VERSION,
    audit_id: auditId,
    plan_path: null,
    created_at: createdAt,
    updated_at: createdAt,
    items: [],
    packets: [],
  };
  await writeTodo(todoPath, todo);
  return { todo, created: true, summary: summarizeAuditTodo(todo) };
}

function recoverExpiredInMemory(todo, timestamp = Date.now()) {
  let recovered = 0;
  const expiredPacketIds = new Set();
  for (const item of todo.items) {
    if (item.status !== "RUNNING" || !item.lease_expires_at) continue;
    if (Date.parse(item.lease_expires_at) > timestamp) continue;
    expiredPacketIds.add(item.packet_id);
    item.status = "PENDING";
    item.packet_id = null;
    item.lease_expires_at = null;
    item.updated_at = now();
    recovered += 1;
  }
  for (const packet of todo.packets) {
    if (expiredPacketIds.has(packet.packet_id) && packet.status === "RUNNING") {
      packet.status = "EXPIRED";
      packet.updated_at = now();
    }
  }
  return recovered;
}

export async function recoverExpiredAuditTodo({ todoPath, nowMs = Date.now() }) {
  const todo = await readAuditTodo(todoPath);
  const recovered = recoverExpiredInMemory(todo, nowMs);
  if (recovered > 0) {
    todo.updated_at = now();
    await writeTodo(todoPath, todo);
  }
  return { recovered, summary: summarizeAuditTodo(todo) };
}

function packetItems(todo, packet) {
  const index = new Map(todo.items.map(item => [item.item_id, item]));
  return packet.item_ids.map(itemId => index.get(itemId)).filter(Boolean);
}

function publicPacket(todo, packet) {
  return {
    packet_id: packet.packet_id,
    audit_id: todo.audit_id,
    agent_name: packet.agent_name,
    status: packet.status,
    lease_expires_at: packet.lease_expires_at,
    item_ids: [...packet.item_ids],
    items: packetItems(todo, packet).map(item => ({
      item_id: item.item_id,
      focus_area_id: item.focus_area_id,
      domain: item.domain,
      assignment_id: item.assignment_id,
      required_lenses: item.required_lenses,
      expected_check_count: item.expected_check_count,
    })),
  };
}

export async function claimAuditTodo({ todoPath, packetLimit = 4, itemsPerPacket = 12, leaseMinutes = DEFAULT_LEASE_MINUTES }) {
  const todo = await readAuditTodo(todoPath);
  recoverExpiredInMemory(todo);
  const requestedPackets = positiveInteger(packetLimit, 4, 32);
  const requestedItems = positiveInteger(itemsPerPacket, 12, 100);
  const minutes = positiveInteger(leaseMinutes, DEFAULT_LEASE_MINUTES, 24 * 60);
  const byAgent = new Map();
  for (const item of todo.items.filter(item => item.status === "PENDING")) {
    const values = byAgent.get(item.agent_name) ?? [];
    values.push(item);
    byAgent.set(item.agent_name, values);
  }
  const packets = [];
  const agents = [...byAgent.keys()].sort((left, right) => {
    const delta = byAgent.get(right).length - byAgent.get(left).length;
    return delta || left.localeCompare(right);
  });
  const deadline = new Date(Date.now() + minutes * 60_000).toISOString();
  for (const agentName of agents) {
    const values = byAgent.get(agentName);
    while (values.length > 0 && packets.length < requestedPackets) {
      const selected = values.splice(0, requestedItems);
      const packet = {
        packet_id: `packet-${randomUUID()}`,
        agent_name: agentName,
        status: "RUNNING",
        item_ids: selected.map(item => item.item_id),
        created_at: now(),
        updated_at: now(),
        lease_expires_at: deadline,
        handoff_path: null,
        failure_reason: null,
      };
      for (const item of selected) {
        item.status = "RUNNING";
        item.packet_id = packet.packet_id;
        item.attempt_count += 1;
        item.lease_expires_at = deadline;
        item.updated_at = now();
      }
      todo.packets.push(packet);
      packets.push(publicPacket(todo, packet));
    }
    if (packets.length >= requestedPackets) break;
  }
  todo.updated_at = now();
  await writeTodo(todoPath, todo);
  const summary = summarizeAuditTodo(todo);
  return { packets, summary, next_action: summary.next_action };
}

async function validateHandoff({ handoffPath, reportsRoot, todo, packet }) {
  const absoluteHandoff = resolve(handoffPath);
  if (!safeChild(reportsRoot, absoluteHandoff)) throw new Error("工作包交付件必须位于受控 reports 目录中。");
  const info = await stat(absoluteHandoff);
  if (!info.isFile() || info.size === 0 || info.size > 8 * 1024 * 1024) throw new Error("工作包交付件不是有效的受控 JSON 文件。");
  let handoff;
  try { handoff = JSON.parse(await readFile(absoluteHandoff, "utf8")); } catch { throw new Error("工作包交付件不是有效 JSON。"); }
  if (!object(handoff) || handoff.schema_version !== 1 || handoff.audit_id !== todo.audit_id || handoff.packet_id !== packet.packet_id || !Array.isArray(handoff.results)) {
    throw new Error("工作包交付件缺少 schema_version、audit_id、packet_id 或 results。");
  }
  const expected = new Set(packet.item_ids);
  const seen = new Set();
  const results = [];
  for (const result of handoff.results) {
    if (!object(result) || typeof result.item_id !== "string" || !expected.has(result.item_id) || seen.has(result.item_id)) {
      throw new Error("工作包交付件包含未知或重复的 item_id。");
    }
    if (!new Set(["DONE", "GAP"]).has(result.status)) throw new Error("工作包交付状态只能是 DONE 或 GAP。");
    if (result.status === "DONE" && (typeof result.report_path !== "string" || !result.report_path)) {
      throw new Error(`DONE 项缺少 report_path：${result.item_id}`);
    }
    if (result.status === "GAP" && (typeof result.gap_reason !== "string" || !result.gap_reason.trim())) {
      throw new Error(`GAP 项缺少 gap_reason：${result.item_id}`);
    }
    let reportPath = null;
    if (typeof result.report_path === "string" && result.report_path) {
      if (isAbsolute(result.report_path)) throw new Error("report_path 必须相对 reports 目录。");
      const candidate = resolve(reportsRoot, result.report_path);
      if (!safeChild(reportsRoot, candidate)) throw new Error("report_path 越出受控 reports 目录。");
      const reportInfo = await stat(candidate);
      if (!reportInfo.isFile() || reportInfo.size === 0) throw new Error(`报告文件不存在或为空：${result.report_path}`);
      reportPath = result.report_path.split(sep).join("/");
    }
    seen.add(result.item_id);
    results.push({
      item_id: result.item_id,
      status: result.status,
      report_path: reportPath,
      finding_ids: Array.isArray(result.finding_ids) ? result.finding_ids.filter(value => typeof value === "string").slice(0, 500) : [],
      gap_reason: typeof result.gap_reason === "string" ? result.gap_reason.trim().slice(0, 4000) : null,
    });
  }
  if (seen.size !== expected.size) throw new Error("工作包交付件没有覆盖该工作包的全部 item_id。");
  return { handoffPath: relative(resolve(reportsRoot), absoluteHandoff).split(sep).join("/"), results };
}

export async function completeAuditTodoPacket({ todoPath, packetId, handoffPath, reportsRoot }) {
  const todo = await readAuditTodo(todoPath);
  const packet = todo.packets.find(candidate => candidate.packet_id === packetId);
  if (!packet) throw new Error("未找到本地工作包。");
  if (packet.status !== "RUNNING") throw new Error(`工作包当前不是 RUNNING：${packet.status}`);
  const handoff = await validateHandoff({ handoffPath, reportsRoot, todo, packet });
  const byItem = new Map(handoff.results.map(result => [result.item_id, result]));
  for (const item of packetItems(todo, packet)) {
    const result = byItem.get(item.item_id);
    item.status = result.status;
    item.packet_id = packet.packet_id;
    item.lease_expires_at = null;
    item.artifact_path = result.report_path;
    item.finding_ids = result.finding_ids;
    item.gap_reason = result.gap_reason;
    item.updated_at = now();
  }
  packet.status = handoff.results.every(result => result.status === "DONE") ? "DONE" : "GAP";
  packet.handoff_path = handoff.handoffPath;
  packet.lease_expires_at = null;
  packet.updated_at = now();
  todo.updated_at = now();
  await writeTodo(todoPath, todo);
  return { packet: publicPacket(todo, packet), summary: summarizeAuditTodo(todo) };
}

export async function failAuditTodoPacket({ todoPath, packetId, reason, retry = true, maxAttempts = DEFAULT_MAX_ATTEMPTS }) {
  const todo = await readAuditTodo(todoPath);
  const packet = todo.packets.find(candidate => candidate.packet_id === packetId);
  if (!packet) throw new Error("未找到本地工作包。");
  if (packet.status !== "RUNNING") throw new Error(`工作包当前不是 RUNNING：${packet.status}`);
  const max = positiveInteger(maxAttempts, DEFAULT_MAX_ATTEMPTS, 20);
  const message = String(reason ?? "工作包执行失败。").trim().slice(0, 4000) || "工作包执行失败。";
  for (const item of packetItems(todo, packet)) {
    const shouldRetry = retry && item.attempt_count < max;
    item.status = shouldRetry ? "PENDING" : "FAILED";
    item.packet_id = shouldRetry ? null : packet.packet_id;
    item.lease_expires_at = null;
    item.gap_reason = message;
    item.updated_at = now();
  }
  packet.status = retry ? "REQUEUED" : "FAILED";
  packet.failure_reason = message;
  packet.lease_expires_at = null;
  packet.updated_at = now();
  todo.updated_at = now();
  await writeTodo(todoPath, todo);
  return { packet: publicPacket(todo, packet), summary: summarizeAuditTodo(todo) };
}

export async function listAuditTodoItems({ todoPath, status = null, offset = 0, limit = 100 }) {
  const todo = await readAuditTodo(todoPath);
  const selected = todo.items.filter(item => !status || item.status === status);
  const start = Math.max(0, Number.isInteger(Number(offset)) ? Number(offset) : 0);
  const size = positiveInteger(limit, 100, 500);
  return {
    audit_id: todo.audit_id,
    total: selected.length,
    returned: selected.slice(start, start + size).length,
    next_offset: start + size < selected.length ? start + size : null,
    items: selected.slice(start, start + size),
    summary: summarizeAuditTodo(todo),
  };
}

export async function auditTodoSummary(todoPath) {
  const todo = await readAuditTodo(todoPath, { allowMissing: true });
  return todo ? summarizeAuditTodo(todo) : null;
}

export function isAuditTodoTerminal(item) {
  return TERMINAL_ITEM_STATES.has(item?.status);
}
