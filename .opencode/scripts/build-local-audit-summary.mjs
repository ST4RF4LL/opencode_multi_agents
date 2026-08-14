#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { auditTodoSummary, readAuditTodo } from "./audit-todo-core.mjs";

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

export async function buildLocalAuditSummary({ auditId, planPath, todoPath }) {
  const [plan, todo] = await Promise.all([
    readFile(resolve(planPath), "utf8").then(JSON.parse),
    readAuditTodo(resolve(todoPath)),
  ]);
  if (plan.audit_id !== auditId || todo.audit_id !== auditId) throw new Error("Plan 或本地任务清单与 audit_id 不一致。");
  if (typeof plan.scope_digest !== "string" || !/^[a-f0-9]{64}$/.test(plan.scope_digest)) throw new Error("Coverage Plan 缺少有效 scope_digest。");
  const summary = await auditTodoSummary(resolve(todoPath));
  if (!summary?.complete) throw new Error("本地任务尚未终态：仍有 PENDING、RUNNING 或 FAILED 项。");
  const closed = summary.done + summary.gap;
  const value = {
    schema_version: 1,
    execution: { model: "local-audit-todo", total_items: summary.total, done_items: summary.done, gap_items: summary.gap },
    audit_id: plan.audit_id,
    scope_digest: plan.scope_digest,
    coverage_status: summary.gap > 0 ? "PARTIAL" : "COMPLETE",
    seal_state: summary.gap > 0 ? "FINALIZED_OBSERVED" : "FINALIZED_COMPLETE",
    policy_mode: "local-todo",
    policy_satisfied: true,
    accounting: { known_coverage: metric(closed, summary.total, summary.gap > 0 ? "GAP_VISIBLE" : "COMPLETE") },
    vulnerability_types: { checks: metric(summary.done, summary.total, summary.gap > 0 ? "GAP_VISIBLE" : "COMPLETE") },
    external_interfaces: { known_checks: metric(summary.done, summary.total, summary.gap > 0 ? "GAP_VISIBLE" : "COMPLETE") },
    files: { checks: metric(summary.done, summary.total, summary.gap > 0 ? "GAP_VISIBLE" : "COMPLETE") },
    functions: { checks: metric(summary.done, summary.total, summary.gap > 0 ? "GAP_VISIBLE" : "COMPLETE") },
    evidence: { attested_checks: metric(summary.done, summary.total, summary.gap > 0 ? "GAP_VISIBLE" : "COMPLETE") },
    local_todo: summary,
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
  });
  const output = resolve(args.output);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ audit_id: value.audit_id, output, coverage_status: value.coverage_status, todo: summary })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
