#!/usr/bin/env node

import { PACKET_REPORT_CONTRACT, validatePacketReports } from "./packet-reports.mjs";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { auditTodoSummary, readAuditTodo } from "./audit-todo-core.mjs";
import { inspectFocusAreaCoverage } from "./focus-area-watchdog.mjs";

function parse(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value == null) throw new Error(`参数无效：${key ?? "<end>"}`);
    values[key.slice(2)] = value;
  }
  for (const key of ["audit-id", "plan", "todo", "output"]) if (!values[key]) throw new Error(`缺少 --${key}`);
  return values;
}

function digest(value) {
  const copy = structuredClone(value);
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

function metric(numerator, denominator, state = "LOCAL_TODO") {
  return {
    numerator,
    denominator,
    percentage: denominator === 0 ? null : Number(((numerator / denominator) * 100).toFixed(2)),
    state,
  };
}

export async function buildLocalAuditSummary({ auditId, planPath, todoPath, reportsRoot = resolve(process.env.AUDIT_REPORTS_ROOT ?? resolve(process.env.AUDIT_WORKSPACE_ROOT ?? process.cwd(), "reports")) }) {
  const [plan, todo] = await Promise.all([
    readFile(resolve(planPath), "utf8").then(JSON.parse),
    readAuditTodo(resolve(todoPath)),
  ]);
  if (plan.audit_id !== auditId || todo.audit_id !== auditId) throw new Error("Plan 或本地任务清单与 audit_id 不一致。");
  if (typeof plan.scope_digest !== "string" || !/^[a-f0-9]{64}$/.test(plan.scope_digest)) throw new Error("Coverage Plan 缺少有效 scope_digest。");
  const summary = await auditTodoSummary(resolve(todoPath));
  if (!summary?.complete) throw new Error("本地任务尚未终态：仍有 PENDING、RUNNING 或 FAILED 项。");
  const focusCheck = await inspectFocusAreaCoverage({ todoPath, reportsRoot });
  if (!focusCheck.complete) throw new Error(`Focus Area 分派未完整核对：${focusCheck.issues.join("；")}；遗漏 ${focusCheck.outstanding.length} 项。`);
  for (const item of todo.items.filter(item => item.status === "DONE" && item.report_contract === PACKET_REPORT_CONTRACT)) {
    await validatePacketReports({ reportsRoot, auditId, item, reports: item.report_bindings });
  }
  const closed = summary.done + summary.gap;
  const focusAreaExceptions = todo.items.filter(item => item.status === "GAP").map(item => ({
    item_id: item.item_id, focus_area_id: item.focus_area_id, assignment_id: item.assignment_id,
    domain: item.domain, agent_name: item.agent_name, status: item.gap_kind === "SKIPPED" ? "SKIPPED" : "GAP", reason: item.gap_reason,
  })).sort((a, b) => a.item_id.localeCompare(b.item_id));
  const residualGaps = [
    ...focusAreaExceptions.map(item => `Focus Area ${item.focus_area_id} / ${item.assignment_id}（${item.agent_name}，${item.domain}，${item.item_id}）${item.status === "SKIPPED" ? "[SKIPPED] 已显式跳过" : "[GAP] 未完成审查"}：${item.reason ?? "未提供原因"}`),
    ...(plan.ai_routing_unknown_file_ids ?? []).map(id => `AI 适用性仍未确认：${id}；不能声明该文件的 AI 风险已排除。`),
  ];
  const hasGaps = residualGaps.length > 0;
  const value = {
    schema_version: 1,
    execution: { model: "local-audit-todo", total_items: summary.total, done_items: summary.done, gap_items: summary.gap },
    audit_id: plan.audit_id,
    scope_digest: plan.scope_digest,
    coverage_status: hasGaps ? "PARTIAL" : "COMPLETE",
    seal_state: hasGaps ? "FINALIZED_OBSERVED" : "FINALIZED_COMPLETE",
    policy_mode: "local-todo",
    policy_satisfied: true,
    accounting: { known_coverage: metric(closed, summary.total, hasGaps ? "GAP_VISIBLE" : "COMPLETE") },
    vulnerability_types: { checks: metric(summary.done, summary.total, hasGaps ? "GAP_VISIBLE" : "COMPLETE") },
    external_interfaces: { known_checks: metric(summary.done, summary.total, hasGaps ? "GAP_VISIBLE" : "COMPLETE") },
    files: { checks: metric(summary.done, summary.total, hasGaps ? "GAP_VISIBLE" : "COMPLETE") },
    functions: { checks: metric(summary.done, summary.total, hasGaps ? "GAP_VISIBLE" : "COMPLETE") },
    evidence: { attested_checks: metric(summary.done, summary.total, hasGaps ? "GAP_VISIBLE" : "COMPLETE") },
    local_todo: summary,
    residual_gaps: residualGaps,
    focus_area_exceptions: focusAreaExceptions,
  };
  value.manifest_digest = digest(value);
  return value;
}

async function main() {
  const args = parse(process.argv.slice(2));
  const value = await buildLocalAuditSummary({
    auditId: args["audit-id"],
    planPath: args.plan,
    todoPath: args.todo,
    ...(args["reports-root"] ? { reportsRoot: args["reports-root"] } : {}),
  });
  const output = resolve(args.output);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ audit_id: value.audit_id, output, coverage_status: value.coverage_status, todo: value.local_todo })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
