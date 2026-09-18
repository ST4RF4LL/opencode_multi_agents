import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { checkPacketHandoff, readAuditTodo } from "./audit-todo-core.mjs";

const hash = value => createHash("sha256").update(value).digest("hex");
const identity = item => ({ item_id: item.item_id, focus_area_id: item.focus_area_id, assignment_id: item.assignment_id, domain: item.domain, agent_name: item.agent_name });

// Read-only: this inspector never accepts reports, requeues work or invents skips.
export async function inspectFocusAreaCoverage({ todoPath, reportsRoot, agentName = null }) {
  const todo = await readAuditTodo(todoPath, { allowMissing: true });
  const issues = [], outstanding = [], exceptions = [], packetChecks = [];
  const selected = item => !agentName || item.agent_name === agentName;
  if (!todo?.items.length) return { initialized: false, complete: false, outstanding, exceptions, issues, packet_checks: packetChecks };
  if (todo.plan_path) {
    try {
      const bytes = await readFile(todo.plan_path), plan = JSON.parse(bytes.toString("utf8"));
      if (plan.audit_id !== todo.audit_id || (todo.plan_sha256 && todo.plan_sha256 !== hash(bytes))) issues.push("Coverage Plan 与当前任务清单的版本绑定不一致。");
      if (!Array.isArray(plan.coverage_units) || !plan.coverage_units.length) throw new Error("Coverage Plan 缺少任务集合。");
      const actual = new Map(todo.items.map(item => [item.item_id, item]));
      const expectedIds = new Set();
      for (const unit of plan.coverage_units) {
        const itemId = `todo:${unit.unit_id}`;
        if (expectedIds.has(itemId)) issues.push(`计划包含重复任务：${itemId}`);
        expectedIds.add(itemId);
        const item = actual.get(itemId);
        if (!item && selected(unit)) outstanding.push({ ...identity({ ...unit, item_id: itemId }), status: "MISSING_TASK", reason: "计划中的分派未进入本地任务清单。" });
        else if (item && ["focus_area_id", "domain", "agent_name"].some(key => item[key] !== unit[key])) issues.push(`任务身份与计划不一致：${itemId}`);
        else if (item && item.assignment_id !== (unit.assignment_id ?? unit.unit_id)) issues.push(`任务责任分派与计划不一致：${itemId}`);
        else if (item && (item.finding_detail_contract ?? null) !== (plan.finding_detail_contract ?? null)) issues.push(`漏洞交付内容契约与计划不一致：${itemId}`);
      }
      for (const item of todo.items) if (!expectedIds.has(item.item_id)) issues.push(`任务不在绑定计划内：${item.item_id}`);
    } catch (error) { issues.push(`无法核对 Coverage Plan：${error.message}`); }
  }
  const submitted = new Map();
  for (const packet of todo.packets.filter(packet => packet.status === "RUNNING" && selected(packet))) {
    if (!/^[a-z0-9._-]+$/i.test(todo.audit_id) || !/^[a-z0-9._-]+$/i.test(packet.packet_id)) {
      issues.push("工作包或审计标识不能用于受控交付路径。");
      continue;
    }
    const handoffPath = join(reportsRoot, "audit-todo", todo.audit_id, `${packet.packet_id}.json`);
    const check = await checkPacketHandoff({ todo, packet, handoffPath, reportsRoot });
    packetChecks.push({ packet_id: packet.packet_id, complete: check.complete, errors: check.errors, missing_items: check.missing_items, invalid_items: check.invalid_items });
    for (const item of check.results) submitted.set(item.item_id, { status: check.complete ? "AWAITING_ACCEPTANCE" : "PACKET_INCOMPLETE", reason: check.complete ? "报告已覆盖分派，等待 Orchestrator 调用 audit-todo complete 验收。" : "本项已提交；同包仍有遗漏或无效结果，尚未验收。" });
    for (const item of check.missing_items) submitted.set(item.item_id, { status: "MISSING_REPORT", reason: "交付件尚未包含本项结果。" });
    for (const item of check.invalid_items) submitted.set(item.item_id, { status: "INVALID_REPORT", reason: item.reason });
  }
  for (const item of todo.items.filter(selected)) {
    if (item.status === "GAP") {
      exceptions.push({ ...identity(item), status: item.gap_kind === "SKIPPED" ? "SKIPPED" : "GAP", reason: item.gap_reason });
    } else if (item.status !== "DONE") {
      const state = submitted.get(item.item_id);
      const expired = item.status === "RUNNING" && Date.parse(item.lease_expires_at) <= Date.now();
      outstanding.push({ ...identity(item), packet_id: item.packet_id, status: expired ? "EXPIRED" : state?.status ?? item.status,
        reason: expired ? "工作包租约已过期，请执行 recover 后重新领取。" : state?.reason ?? (item.status === "PENDING" ? "尚未领取或等待重试。" : item.gap_reason || "尚未完成分派审计。") });
    }
  }
  const result = { schema_version: 1, audit_id: todo.audit_id, initialized: true, complete: outstanding.length === 0 && issues.length === 0,
    total_items: todo.items.filter(selected).length, done_items: todo.items.filter(item => selected(item) && item.status === "DONE").length,
    outstanding, exceptions, issues, packet_checks: packetChecks };
  result.fingerprint = hash(JSON.stringify(result));
  return result;
}

export function formatFocusAreaReminder(check, { limit = 12 } = {}) {
  if (!check.initialized || check.complete) return "";
  const line = value => String(value).replace(/[\r\n]+/g, " ").slice(0, 600);
  const rows = check.outstanding.slice(0, limit).map(item => line(`- ${item.focus_area_id} / ${item.assignment_id} · ${item.agent_name} · ${item.status}：${item.reason}`));
  const packetErrors = (check.packet_checks ?? []).flatMap(packet => packet.errors.map(error => line(`工作包 ${packet.packet_id}：${error}`))).slice(0, 4);
  return [
    `[Focus Area watchdog] 仍有 ${check.outstanding.length} 项未完成分派，${check.issues.length} 项计划核对异常。`,
    ...check.issues.slice(0, 5).map(line), ...packetErrors, ...rows,
    ...(check.outstanding.length > limit ? [`其余 ${check.outstanding.length - limit} 项请用 audit-todo list 分页查看；本消息不是完整任务清单。`] : []),
    "请补齐交付并运行 audit-todo check / complete；缺项不能当作无漏洞或自动跳过。特殊情况用 status=GAP、gap_kind=SKIPPED、非空 gap_reason 显式交付，跳过原因会进入最终报告且不计为有效完成。",
    "仅处理自己领取的工作包；其他包中的 PENDING 由 Orchestrator 继续调度，已接受的 DONE/GAP 不得因提醒重开。",
  ].join("\n");
}
