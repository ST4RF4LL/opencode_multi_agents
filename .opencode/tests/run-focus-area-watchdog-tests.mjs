import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { initializeAuditTodo, claimAuditTodo, checkAuditTodoPacket, completeAuditTodoPacket, readAuditTodo, auditTodoSummary } from "../scripts/audit-todo-core.mjs";
import { inspectFocusAreaCoverage, formatFocusAreaReminder } from "../scripts/focus-area-watchdog.mjs";
import { buildLocalAuditSummary } from "../scripts/build-local-audit-summary.mjs";
import focusPlugin from "../lib/focus-area-watchdog-plugin.mjs";
import { AuditRunner } from "../web/dynamic-validation-observatory/audit-runner.mjs";
import { finalReportModelDigest, validateFinalReportModel, renderFinalReport } from "../skills/common-subagent/audit-coverage-accounting/scripts/final-report-model-core.mjs";
import { exampleFinding } from "./fixtures/report-details.mjs";

const hash = value => createHash("sha256").update(value).digest("hex");
const lenses = ["sink-driven", "control-driven", "config-driven"];
async function fixture(t, { splitDomain = false, detailContract = false } = {}) {
  const root = await mkdtemp(join(tmpdir(), "focus-watchdog-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const auditId = "audit-focus-watchdog", reportsRoot = join(root, "reports"), todoPath = join(root, "todo.json"), planPath = join(root, "plan.json");
  const plan = { audit_id: auditId, scope_digest: "a".repeat(64), packet_report_contract: "tri-lens-v2", coverage_units: ["a", "b"].map(id => ({
    unit_id: id, focus_area_id: `focus-${id}`, assignment_id: `assignment-${id}`, domain: "java", agent_name: "java-source-auditor", required_lenses: lenses,
  })) };
  if (splitDomain) Object.assign(plan.coverage_units[1], { focus_area_id: "focus-a", domain: "web", agent_name: "web-source-auditor" });
  if (detailContract) plan.finding_detail_contract = "finding-details.v1";
  await mkdir(join(reportsRoot, "audit-todo", auditId), { recursive: true });
  await writeFile(planPath, JSON.stringify(plan));
  await initializeAuditTodo({ todoPath, planPath, auditId });
  const packet = (await claimAuditTodo({ todoPath })).packets[0];
  const handoffPath = join(reportsRoot, "audit-todo", auditId, `${packet.packet_id}.json`);
  const reports = [];
  for (const lens of lenses) {
    const report = { audit_id: auditId, scope_digest: plan.scope_digest, agent_name: "java-source-auditor", focus_area_id: "focus-a", agent_session_id: "session-java", audit_strategy: lens, discovery_track: "coverage", scope: { focus_assignment_id: "assignment-a" }, findings: [] };
    const bytes = JSON.stringify(report), path = `${lens}.json`;
    await writeFile(join(reportsRoot, path), bytes);
    reports.push({ lens, path, sha256: hash(bytes) });
  }
  const results = [{ item_id: packet.item_ids[0], status: "DONE", reports }];
  const submit = async rows => writeFile(handoffPath, JSON.stringify({ schema_version: 1, audit_id: auditId, packet_id: packet.packet_id, results: rows }));
  await submit(results);
  return { root, reportsRoot, todoPath, planPath, auditId, plan, packet, handoffPath, results, submit, packetId: packet.packet_id };
}

test("新交付内容契约进入分派和 watchdog；不完整候选不能交卷", async t => {
  const f = await fixture(t, { detailContract: true });
  assert.equal((await readAuditTodo(f.todoPath)).items[0].finding_detail_contract, "finding-details.v1");
  const binding = f.results[0].reports[0], reportPath = join(f.reportsRoot, binding.path);
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  const finding = exampleFinding(); delete finding.report_details;
  report.findings = [finding];
  const update = async () => {
    const bytes = JSON.stringify(report); await writeFile(reportPath, bytes); binding.sha256 = hash(bytes);
    await f.submit([...f.results, { item_id: f.packet.item_ids[1], status: "GAP", gap_kind: "SKIPPED", gap_reason: "缺少第二处源码。" }]);
  };
  await update();
  const check = await checkAuditTodoPacket(f);
  assert.equal(check.complete, false); assert.match(check.invalid_items[0].reason, /finding-report-details-missing/);
  assert.match(formatFocusAreaReminder(await inspectFocusAreaCoverage(f)), /focus-a.*finding-report-details-missing/);
  await assert.rejects(completeAuditTodoPacket(f), /交付内容不足/);
  report.findings = [exampleFinding()]; await update();
  assert.equal((await checkAuditTodoPacket(f)).complete, true);
  await completeAuditTodoPacket(f);
  const unknown = { ...f.plan, finding_detail_contract: "finding-details.v99" };
  await writeFile(join(f.root, "unknown-plan.json"), JSON.stringify(unknown));
  await assert.rejects(initializeAuditTodo({ todoPath: join(f.root, "new-todo.json"), planPath: join(f.root, "unknown-plan.json"), auditId: f.auditId }), /版本不受支持/);
});

test("漏交返回具体 Area；拒绝整包提交且不改动队列", async t => {
  const f = await fixture(t), before = await readFile(f.todoPath, "utf8");
  const check = await checkAuditTodoPacket(f);
  assert.equal(check.complete, false);
  assert.deepEqual(check.missing_items.map(item => item.focus_area_id), ["focus-b"]);
  await assert.rejects(completeAuditTodoPacket(f), /遗漏 focus-b/);
  assert.equal(await readFile(f.todoPath, "utf8"), before);
  const global = await inspectFocusAreaCoverage(f);
  assert.equal(global.outstanding.find(item => item.focus_area_id === "focus-b").status, "MISSING_REPORT");
  assert.match(formatFocusAreaReminder(global), /focus-b.*assignment-b.*java-source-auditor/);
  try {
    execFileSync(process.execPath, [fileURLToPath(new URL("../scripts/audit-todo.mjs", import.meta.url)), "check", "--todo", f.todoPath, "--packet", f.packetId, "--handoff", f.handoffPath, "--reports-root", f.reportsRoot], { encoding: "utf8", stdio: "pipe" });
    assert.fail("遗漏必须非零退出");
  } catch (error) {
    assert.equal(error.status, 1);
    assert.equal(JSON.parse(error.stdout).missing_items[0].focus_area_id, "focus-b");
  }
});

test("无效三视角、重复/越域交付、缺理由跳过都不能完成", async t => {
  const f = await fixture(t);
  await f.submit([{ ...f.results[0], reports: f.results[0].reports.slice(1) }, { item_id: f.packet.item_ids[1], status: "GAP", gap_kind: "SKIPPED", gap_reason: " " }]);
  const invalid = await checkAuditTodoPacket(f);
  assert.equal(invalid.invalid_items.length, 2);
  assert.match(invalid.invalid_items[0].reason, /三个/);
  assert.match(invalid.invalid_items[1].reason, /非空/);
  await f.submit([...f.results, f.results[0], { item_id: "another-agent-item", status: "GAP", gap_reason: "越域" }]);
  assert.equal((await checkAuditTodoPacket(f)).errors.length, 2);
  await f.submit([{ ...f.results[0], gap_kind: "SKIPPED" }]);
  assert.match((await checkAuditTodoPacket(f)).invalid_items[0].reason, /status=GAP/);
});

test("同一 Area 的多个责任域独立验收，一方完成不能掩盖另一方遗漏", async t => {
  const f = await fixture(t, { splitDomain: true });
  await completeAuditTodoPacket(f);
  const java = await inspectFocusAreaCoverage({ ...f, agentName: "java-source-auditor" });
  const web = await inspectFocusAreaCoverage({ ...f, agentName: "web-source-auditor" });
  const all = await inspectFocusAreaCoverage(f);
  assert.equal(java.complete, true);
  assert.equal(web.complete, false);
  assert.equal(all.outstanding.length, 1);
  assert.equal(all.outstanding[0].focus_area_id, "focus-a");
  assert.equal(all.outstanding[0].agent_name, "web-source-auditor");
  assert.equal(all.outstanding[0].assignment_id, "assignment-b");
});

async function skippedFixture(t) {
  const f = await fixture(t);
  await f.submit([...f.results, { item_id: f.packet.item_ids[1], status: "GAP", gap_kind: "SKIPPED", gap_reason: "依赖源码未提供，本次无法审查。" }]);
  assert.equal((await checkAuditTodoPacket(f)).complete, true);
  const waiting = await inspectFocusAreaCoverage(f);
  assert.ok(waiting.outstanding.every(item => item.status === "AWAITING_ACCEPTANCE"));
  await completeAuditTodoPacket(f);
  return f;
}

function reportModel(auditId, summary) {
  const model = { schema_version: 1, audit_id: auditId, scope_digest: "a".repeat(64), report_kind: "POLICY_FINAL",
    coverage: { summary_digest: summary.manifest_digest, coverage_status: summary.coverage_status, seal_state: summary.seal_state, policy_mode: "local-todo", policy_satisfied: true, metrics: [] },
    inputs: Object.fromEntries(["coverage_summary", "adjudication_input", "adjudication", "truth_validation_intake", "quick_dynamic_results", "affirmative_review", "negative_review", "moderator_review", "validation_routing", "cvss_assessment", "attack_chains"].map(key => [key, `reports/${key}.json`])),
    truth_validation: { routing_digest: "c".repeat(64), full_dynamic_trigger: "MANUAL_ONLY", summary: { total: 0, true_positive: 0, false_positive: 0, inconclusive: 0 }, source: { artifact: "reports/routing.json", digest: "c".repeat(64), json_pointer: "/summary" } },
    findings: [], excluded_findings: [], chains: [], rejected_chains: [], residual_gaps: summary.residual_gaps, focus_area_exceptions: summary.focus_area_exceptions };
  model.manifest_digest = finalReportModelDigest(model);
  return model;
}

test("显式跳过保留为 GAP，不计 DONE，生成中文跳过清单", async t => {
  const f = await skippedFixture(t), stats = await auditTodoSummary(f.todoPath);
  assert.equal(stats.complete, true);
  assert.equal(stats.done, 1); assert.equal(stats.skipped, 1); assert.equal(stats.gap, 1);
  const check = await inspectFocusAreaCoverage(f);
  assert.equal(formatFocusAreaReminder(check), "", "接受的跳过不反复催办");
  const summary = await buildLocalAuditSummary(f);
  assert.equal(summary.coverage_status, "PARTIAL");
  assert.equal(summary.vulnerability_types.checks.percentage, 50);
  const model = reportModel(f.auditId, summary);
  assert.deepEqual(validateFinalReportModel(model), []);
  const markdown = renderFinalReport(model);
  assert.match(markdown, /Focus Area 跳过与未完成清单/);
  assert.match(markdown, /focus-b \/ assignment-b.*SKIPPED.*依赖源码未提供/);
  const malformed = { ...model, focus_area_exceptions: null };
  assert.ok(validateFinalReportModel(malformed).includes("final-report-focus-area-exceptions-invalid"));
});

test("计划任务被删或同路径计划变更不会静默变为覆盖完成", async t => {
  const f = await skippedFixture(t);
  const todo = await readAuditTodo(f.todoPath);
  todo.items = todo.items.slice(0, 1);
  await writeFile(f.todoPath, JSON.stringify(todo));
  const check = await inspectFocusAreaCoverage(f);
  assert.equal(check.complete, false);
  assert.equal(check.outstanding[0].status, "MISSING_TASK");
  await assert.rejects(buildLocalAuditSummary(f), /遗漏 1 项/);
  await writeFile(f.planPath, JSON.stringify({ ...f.plan, extra: "changed" }));
  await assert.rejects(initializeAuditTodo(f), /Plan 已变更/);
  assert.ok((await inspectFocusAreaCoverage(f)).issues.some(issue => /版本绑定/.test(issue)));
});

test("watchdog 定期发出具体提醒，去重并保留完整机器检查结果", async t => {
  const f = await fixture(t), events = [], logs = [];
  const audit = { id: f.auditId, todo_path: f.todoPath, status: "running", stage_delivery_enforcement: "TODO_ENFORCED" };
  const runner = Object.assign(Object.create(AuditRunner.prototype), {
    stateRoot: f.root, audits: new Map([[audit.id, audit]]), processes: new Map([[audit.id, {}]]),
    reportsRootForAudit: () => f.reportsRoot, reconcileFinalReportArtifacts: async () => {}, reconcileManagedCompletion: async () => false,
    record: async (_audit, type, data) => events.push({ type, data }), recordLog: async (_audit, _source, message) => logs.push(message),
  });
  await mkdir(join(f.root, audit.id));
  await runner.runCompletionWatchdog();
  await runner.runCompletionWatchdog();
  assert.equal(events.length, 1); assert.equal(events[0].type, "audit.focus-area.reminder");
  assert.match(logs[0], /focus-b/);
  assert.equal(JSON.parse(await readFile(join(f.root, audit.id, "focus-area-coverage.json"), "utf8")).outstanding.length, 2);
  await f.submit([...f.results, { item_id: f.packet.item_ids[1], status: "GAP", gap_kind: "SKIPPED", gap_reason: "缺少依赖源码。" }]);
  await completeAuditTodoPacket(f);
  await runner.runCompletionWatchdog();
  assert.equal(events.at(-1).type, "audit.focus-area.accounted");
  assert.equal(audit.focus_area_watchdog.skipped_count, 1);
});

test("提醒注入 task 返回及本会话工具结果，按责任域隔离且不重复刷屏", async t => {
  const f = await fixture(t);
  const hooks = await focusPlugin({ watchdogEnvironment: { AUDIT_TODO_PATH: f.todoPath, AUDIT_REPORTS_ROOT: f.reportsRoot } });
  const input = { tool: "task", sessionID: "parent", args: { subagent_type: "java-source-auditor" } };
  const output = { output: "专业报告已提交。" };
  await hooks["tool.execute.after"](input, output);
  assert.match(output.output, /Focus Area watchdog.*\n/s);
  assert.match(output.output, /focus-b/);
  const repeated = { output: "再次返回。" };
  await hooks["tool.execute.after"](input, repeated);
  assert.equal(repeated.output, "再次返回。");
  await hooks["chat.message"]({ sessionID: "child", agent: "java-source-auditor" });
  const childOutput = { output: "写入报告。" };
  await hooks["tool.execute.after"]({ tool: "write", sessionID: "child" }, childOutput);
  assert.match(childOutput.output, /focus-b/);
  const other = { output: "Web 已提交。" };
  await hooks["tool.execute.after"]({ ...input, sessionID: "web", args: { subagent_type: "web-source-auditor" } }, other);
  assert.equal(other.output, "Web 已提交。");
  await writeFile(f.todoPath, "invalid JSON");
  const unavailable = { output: "完成。" };
  await hooks["tool.execute.after"]({ ...input, sessionID: "broken" }, unavailable);
  assert.match(unavailable.output, /UNAVAILABLE/);
});

test("收尾门禁拒绝报告隐藏或改写跳过原因", async t => {
  const f = await skippedFixture(t), summary = await buildLocalAuditSummary(f), model = reportModel(f.auditId, summary);
  const runner = new AuditRunner({ stateRoot: join(f.root, "runner"), enabled: false });
  await runner.ready; t.after(() => runner.shutdown());
  runner.reportsRootForAudit = () => f.reportsRoot;
  const audit = { id: f.auditId, todo_path: f.todoPath };
  const path = join(f.reportsRoot, "final", `security-audit-report-model.${f.auditId}.json`);
  await mkdir(join(f.reportsRoot, "final"));
  const save = async value => { value.manifest_digest = finalReportModelDigest(value); await writeFile(path, JSON.stringify(value)); };
  await save(model);
  assert.equal((await runner.verifyTodoCompletion(audit)).complete, true);
  model.focus_area_exceptions = [];
  await save(model);
  const hidden = await runner.verifyTodoCompletion(audit);
  assert.equal(hidden.complete, false); assert.ok(hidden.errors.some(error => /SKIPPED Focus Area/.test(error)));
  model.focus_area_exceptions = [{ ...summary.focus_area_exceptions[0], reason: "伪造原因" }];
  await save(model);
  assert.equal((await runner.verifyTodoCompletion(audit)).complete, false);
});
