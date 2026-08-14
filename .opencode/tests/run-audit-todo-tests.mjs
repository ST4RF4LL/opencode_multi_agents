#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  auditTodoSummary,
  claimAuditTodo,
  completeAuditTodoPacket,
  createEmptyAuditTodo,
  failAuditTodoPacket,
  initializeAuditTodo,
  listAuditTodoItems,
  readAuditTodo,
  recoverExpiredAuditTodo,
} from "../scripts/audit-todo-core.mjs";
import { buildLocalAuditSummary } from "../scripts/build-local-audit-summary.mjs";

const root = await mkdtemp(join(tmpdir(), "audit-todo-"));
const reportsRoot = join(root, "reports");
const todoPath = join(root, "state", "audit-todo.json");
const planPath = join(root, "coverage-plan.json");
const auditId = "audit-todo-001";

function plan() {
  return {
    audit_id: auditId,
    scope_digest: "a".repeat(64),
    coverage_units: [
      { unit_id: "java-a", focus_area_id: "focus-a", domain: "java", agent_name: "java-source-auditor", assignment_id: "assignment-a", required_lenses: ["sink", "control", "config"], required_source_set_id: "source-a", check_ids: ["a-1", "a-2"] },
      { unit_id: "java-b", focus_area_id: "focus-b", domain: "java", agent_name: "java-source-auditor", assignment_id: "assignment-b", required_lenses: ["sink", "control", "config"], required_source_set_id: "source-b", check_ids: ["b-1"] },
      { unit_id: "web-a", focus_area_id: "focus-c", domain: "web", agent_name: "web-source-auditor", assignment_id: "assignment-c", required_lenses: ["sink", "control", "config"], required_source_set_id: "source-c", check_ids: ["c-1"] },
    ],
  };
}

try {
  await mkdir(reportsRoot, { recursive: true });
  await writeFile(planPath, `${JSON.stringify(plan(), null, 2)}\n`, "utf8");

  const empty = await createEmptyAuditTodo({ todoPath, auditId });
  assert.equal(empty.summary.total, 0, "新任务先创建空清单");
  const initialized = await initializeAuditTodo({ todoPath, auditId, planPath });
  assert.equal(initialized.created, true, "空清单必须能由计划初始化");
  assert.equal(initialized.summary.total, 3, "一个 coverage unit 对应一个本地任务");
  assert.equal(initialized.todo.items[0].required_lenses.length, 3, "三个 lens 不得拆为 UI todo 项");
  assert.equal((await initializeAuditTodo({ todoPath, auditId, planPath })).created, false, "同一计划重复初始化必须幂等");

  const claimed = await claimAuditTodo({ todoPath, packetLimit: 4, itemsPerPacket: 1, leaseMinutes: 30 });
  assert.equal(claimed.packets.length, 3, "应按专业 Agent 和包上限领取有限工作包");
  assert.equal(claimed.summary.running, 3);
  const [first, second, third] = claimed.packets;

  await mkdir(join(reportsRoot, "vulnerability-mining"), { recursive: true });
  await mkdir(join(reportsRoot, "audit-todo", auditId), { recursive: true });
  const reportPath = "vulnerability-mining/java-a.audit-report.json";
  await writeFile(join(reportsRoot, reportPath), `${JSON.stringify({ audit_id: auditId, findings: [] })}\n`, "utf8");
  const firstHandoffPath = join(reportsRoot, "audit-todo", auditId, `${first.packet_id}.json`);
  await writeFile(firstHandoffPath, `${JSON.stringify({ schema_version: 1, audit_id: auditId, packet_id: first.packet_id, results: [{ item_id: first.item_ids[0], status: "DONE", report_path: reportPath, finding_ids: ["F-001"] }] })}\n`, "utf8");
  const complete = await completeAuditTodoPacket({ todoPath, packetId: first.packet_id, handoffPath: firstHandoffPath, reportsRoot });
  assert.equal(complete.summary.done, 1);

  await failAuditTodoPacket({ todoPath, packetId: second.packet_id, reason: "scanner timeout", retry: true });
  assert.equal((await auditTodoSummary(todoPath)).pending, 1, "可恢复失败应重新入队");
  const retryPacket = (await claimAuditTodo({ todoPath, packetLimit: 1, itemsPerPacket: 12 })).packets[0];
  await failAuditTodoPacket({ todoPath, packetId: retryPacket.packet_id, reason: "授权范围缺少依赖", retry: false });
  assert.equal((await auditTodoSummary(todoPath)).failed, 1, "不可恢复失败必须保持可见");

  const todo = await readAuditTodo(todoPath);
  const runningItem = todo.items.find(item => item.packet_id === third.packet_id);
  runningItem.lease_expires_at = "2000-01-01T00:00:00.000Z";
  await writeFile(todoPath, `${JSON.stringify(todo, null, 2)}\n`, "utf8");
  const recovered = await recoverExpiredAuditTodo({ todoPath, nowMs: Date.now() });
  assert.equal(recovered.recovered, 1, "过期 RUNNING 工作包必须重新入队");
  assert.equal(recovered.summary.pending, 1);

  const pending = await listAuditTodoItems({ todoPath, status: "PENDING", limit: 10 });
  assert.equal(pending.total, 1);
  assert.equal(pending.items[0].item_id, runningItem.item_id);
  assert.equal((await auditTodoSummary(todoPath)).complete, false, "FAILED 项不可被误判为完成");

  const summaryAuditId = "audit-todo-summary";
  const summaryTodoPath = join(root, "state", "summary-todo.json");
  const summaryPlanPath = join(root, "summary-plan.json");
  const summaryOutputPath = join(reportsRoot, "coverage", `coverage-summary.${summaryAuditId}.json`);
  const summaryPlan = plan();
  summaryPlan.audit_id = summaryAuditId;
  await writeFile(summaryPlanPath, `${JSON.stringify(summaryPlan, null, 2)}\n`, "utf8");
  await initializeAuditTodo({ todoPath: summaryTodoPath, auditId: summaryAuditId, planPath: summaryPlanPath });
  const summaryPackets = await claimAuditTodo({ todoPath: summaryTodoPath, packetLimit: 4, itemsPerPacket: 12 });
  for (const packet of summaryPackets.packets) {
    const handoffPath = join(reportsRoot, "audit-todo", summaryAuditId, `${packet.packet_id}.json`);
    const results = [];
    for (const itemId of packet.item_ids) {
      const report = `vulnerability-mining/${itemId.replaceAll(":", "-")}.json`;
      await writeFile(join(reportsRoot, report), `${JSON.stringify({ audit_id: summaryAuditId, findings: [] })}\n`, "utf8");
      results.push({ item_id: itemId, status: "DONE", report_path: report });
    }
    await mkdir(join(reportsRoot, "audit-todo", summaryAuditId), { recursive: true });
    await writeFile(handoffPath, `${JSON.stringify({ schema_version: 1, audit_id: summaryAuditId, packet_id: packet.packet_id, results })}\n`, "utf8");
    await completeAuditTodoPacket({ todoPath: summaryTodoPath, packetId: packet.packet_id, handoffPath, reportsRoot });
  }
  assert.equal((await auditTodoSummary(summaryTodoPath)).complete, true);
  const builtLocalSummary = await buildLocalAuditSummary({ auditId: summaryAuditId, planPath: summaryPlanPath, todoPath: summaryTodoPath });
  await mkdir(join(reportsRoot, "coverage"), { recursive: true });
  await writeFile(summaryOutputPath, `${JSON.stringify(builtLocalSummary, null, 2)}\n`, "utf8");
  const localSummary = JSON.parse(await readFile(summaryOutputPath, "utf8"));
  assert.equal(localSummary.execution.model, "local-audit-todo");
  assert.equal(localSummary.coverage_status, "COMPLETE");
  assert.match(localSummary.manifest_digest, /^[a-f0-9]{64}$/);
  process.stdout.write("audit todo tests passed\n");
} finally {
  await rm(root, { recursive: true, force: true });
}
