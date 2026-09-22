import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, rm, symlink, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { bacFixture, readJson, writeJson, reviewedFinding } from "./fixtures/bac.mjs";
import { compareBac, prepareBac, prepareReview, reviewBac, validateRequest } from "../lib/bac/service.mjs";
import { BAC_CONTRACT, bacForUnit, bacSelection, objectDigest, seal, sha256, validateBacAttachment, validateComparison, validateReview, verifyEvidenceSources } from "../lib/bac/contract.mjs";
import { buildBacSummary, renderBacSummary, validateBacSummary } from "../lib/bac/summary.mjs";
import { bacStageRegistry } from "../lib/bac/stage-registry.mjs";
import { runtimeStageRegistry } from "../lib/runtime-testing/stage-registry.mjs";
import { validateStageContractRegistry } from "../skills/common-subagent/audit-artifact-management/scripts/stage-agent-contract.mjs";
import { validatePacketReports } from "../scripts/packet-reports.mjs";
import { initializeAuditTodo, claimAuditTodo, completeAuditTodoPacket } from "../scripts/audit-todo-core.mjs";
import { buildLocalAuditSummary } from "../scripts/build-local-audit-summary.mjs";
import { inspectFocusAreaCoverage } from "../scripts/focus-area-watchdog.mjs";
import { verifyBacFinalReport } from "../lib/bac/final-verification.mjs";

async function fixture(t) { const value = await bacFixture(); t.after(() => rm(value.root, { recursive: true, force: true })); return value; }
async function compare(value, edit = () => {}) {
  edit(value.request); await writeJson(value.requestPath, value.request);
  const output = await compareBac({ requestPath: value.requestPath, reportsRoot: value.reports });
  return { output, run: await readJson(output.run_path) };
}

test("有证据的缺少所有者校验形成静态候选，不自动确认", async t => {
  const f = await fixture(t), { run, output } = await compare(f);
  assert.equal(run.result.findings[0].classification, "BHAC_CANDIDATE");
  assert.equal(run.result.findings[0].validation_status, "NOT_PERFORMED");
  assert.equal(run.result.summary.analysis_complete, true);
  assert.equal(run.result.path_results.length, 1);
  assert.match(await readFile(join(f.reports, "bac", f.plan.audit_id, "runs/run-1/bac-findings.md"), "utf8"), /越权专项/);
  const sarif = await readJson(join(f.reports, "bac", f.plan.audit_id, "runs/run-1/result.sarif"));
  assert.equal(sarif.runs[0].results.length, 1);
  assert.equal(output.candidates, 1);
  await assert.rejects(compareBac({ requestPath: f.requestPath, reportsRoot: f.reports }));
});

for (const [name, edit, verify] of [
  ["无证据控制断言保持未知", r => r.paths.paths[0].implemented_controls.hac.evidence = [], r => { assert.equal(r.findings.length, 0); assert.equal(r.inconclusive.length, 1); }],
  ["遗漏控制字段保持未知", r => delete r.paths.paths[0].implemented_controls.hac, r => assert.deepEqual(r.inconclusive[0].unknown_controls, ["HAC"])],
  ["不可达缺少证据不能抑制", r => r.paths.paths[0].reachability = { status: "UNREACHABLE", evidence: [] }, r => { assert.equal(r.suppressed_paths.length, 0); assert.equal(r.findings.length, 1); assert.equal(r.summary.analysis_complete, false); }],
  ["有证据不可达单独计数", r => r.paths.paths[0].reachability.status = "UNREACHABLE", r => { assert.equal(r.findings.length, 0); assert.equal(r.suppressed_paths.length, 1); }],
  ["内部接口不降低置信度", r => r.paths.paths[0].entrypoint.interface_type = "INTERNAL", r => assert.equal(r.findings[0].confidence, .96)],
  ["候选中的未知控制必须保留缺口", r => { delete r.paths.paths[0].implemented_controls.vac; }, r => { assert.equal(r.findings.length, 1); assert.deepEqual(r.findings[0].unknown_controls, ["VAC"]); assert.equal(r.summary.analysis_complete, false); }],
  ["逐路径 PARTIAL 不得显示完整", r => r.paths.paths[0].coverage = "PARTIAL", r => assert.equal(r.summary.analysis_complete, false)],
  ["逐路径 known_gaps 不丢弃", r => r.paths.paths[0].known_gaps = ["动态 SQL 分支未解析。"], r => assert.ok(r.limitations.some(g => g.code === "PATH_GAP"))],
  ["完整性缺少审查依据仍保留缺口", r => delete r.acp.coverage.evidence, r => assert.ok(r.limitations.some(g => g.code === "INPUT_COVERAGE_UNPROVEN"))],
  ["未决 ACP 不丢弃", r => r.acp.unresolved = [{ reason: "角色映射冲突。" }], r => assert.equal(r.summary.analysis_complete, false)],
  ["已关联入口仍保留未知相关性", r => r.api_catalog.apis[0].database_relevant = null, r => assert.equal(r.coverage_gaps.unknown_api_relevance.length, 1)],
  ["空路径不能覆盖数据库入口", r => r.paths.paths = [], r => assert.equal(r.coverage_gaps.uncovered_apis.length, 1)],
  ["全为有效控制输出明确无差分路径", r => { for (const key of Object.keys(r.paths.paths[0].implemented_controls.hac)) if (key !== "evidence") r.paths.paths[0].implemented_controls.hac[key] = true; }, r => assert.equal(r.path_results[0].state, "NO_MISMATCH")],
  ["角色与所有者控制同时缺失保留双分类", r => { r.paths.paths[0].implemented_controls.vac.role_match = false; }, r => assert.equal(r.findings[0].classification, "BVAC_BHAC_CANDIDATE")],
  ["有据公开策略 NONE 不强加 VAC 或 HAC", r => { r.acp.quadruples[0].tuple.AC = "NONE"; r.paths.paths[0].policy_binding.AC = "NONE"; }, r => { assert.equal(r.findings.length, 0); assert.equal(r.path_results[0].state, "NO_MISMATCH"); }],
  ["兼容角色精确匹配失败保留未匹配路径", r => { delete r.paths.paths[0].policy_binding; r.paths.paths[0].effective_role = "GUEST"; }, r => { assert.equal(r.path_results[0].state, "UNMATCHED"); assert.equal(r.coverage_gaps.unreferenced_acp.length, 1); }],
  ["没有独立策略证据不能产生候选", r => r.acp.quadruples[0].evidence = [], r => { assert.equal(r.findings.length, 0); assert.equal(r.path_results[0].state, "INCONCLUSIVE"); }],
  ["已知 revision 冲突不得完整", r => r.api_catalog.repository = { ...r.api_catalog.repository, revision: "other" }, r => assert.equal(r.summary.analysis_complete, false)],
]) test(name, async t => { const f = await fixture(t); const { run } = await compare(f, edit); verify(run.result); });

test("低权限调用者与 ADMIN 策略分离，垂直越权进入差分", async t => {
  const f = await fixture(t);
  const { run } = await compare(f, r => {
    r.acp.quadruples[0].tuple = { D: "shop.orders", O: "READ", R: "ADMIN", AC: "VAC" };
    r.resource_role_catalog.roles.push({ R: "ADMIN", evidence: [f.evidence()] });
    r.paths.paths[0].policy_binding = r.acp.quadruples[0].tuple;
    r.paths.paths[0].implemented_controls.vac.role_match = false;
  });
  assert.equal(run.result.findings[0].classification, "BVAC_CANDIDATE");
  assert.deepEqual(run.result.findings[0].caller_context.roles, ["MEMBER"]);
  assert.equal(run.result.findings[0].tuple_ref.R, "ADMIN");
});

test("模型外权限保留为专项缺口，不扩大四元组", async t => {
  const f = await fixture(t);
  const { output, run } = await compare(f, r => { r.acp.out_of_model = [{ kind: "TENANT", reason: "租户隔离继续常规权限审计。", evidence: [f.evidence()] }]; });
  assert.equal(output.status, "PARTIAL");
  assert.equal(run.result.out_of_model.length, 1);
  assert.deepEqual(Object.keys(run.result.findings[0].tuple_ref).sort(), ["AC", "D", "O", "R"]);
});

test("输入顺序不影响其他路径的置信度或结果", async t => {
  const f = await fixture(t);
  const unknown = structuredClone(f.request.paths.paths[0]); unknown.path_id = "path-unknown"; unknown.known_gaps = ["未解析分支。"];
  f.request.paths.paths.push(unknown);
  const first = (await compare(f)).run.result;
  f.request.run_id = "run-2"; f.request.paths.paths.reverse();
  const second = (await compare(f)).run.result;
  assert.deepEqual(first, second);
});

test("伪造类型、重复四元组与扩维输入被拒绝", async t => {
  const f = await fixture(t), original = structuredClone(f.request);
  for (const edit of [r => r.acp.quadruples.push(structuredClone(r.acp.quadruples[0])), r => r.acp.quadruples[0].tuple.tenant = "x", r => r.paths.paths[0].implemented_controls.vac.observed = "false"]) {
    f.request = structuredClone(original); edit(f.request); await writeJson(f.requestPath, f.request);
    await assert.rejects(compareBac({ requestPath: f.requestPath, reportsRoot: f.reports }));
  }
});

test("输入必须独立生产、同范围、完整保留入口", async t => {
  const f = await fixture(t);
  for (const edit of [r => r.acp.producer.agent_session_id = r.producer.agent_session_id, r => r.api_catalog.repository.scope_digest = "b".repeat(64), r => r.api_catalog.apis = [], r => r.resource_role_catalog.roles = []]) {
    const request = structuredClone(f.request); edit(request); assert.throws(() => validateRequest(request, f.plan));
  }
  await writeFile(join(f.source, "src/OrderService.java"), "changed source");
  await assert.rejects(compareBac({ requestPath: f.requestPath, reportsRoot: f.reports }), /源码自冻结后发生变化/);
});

test("源码证据位置及来源必须可复核", async t => {
  const f = await fixture(t);
  for (const locator of [{ ...f.locator(1), file: "../outside.java" }, { ...f.locator(999) }, { ...f.locator(1), source_digest: "b".repeat(64) }]) {
    await assert.rejects(verifyEvidenceSources(f.plan, f.source, { evidence: [{ kind: "source", claim: "无效引用。", locator }] }));
  }
});

test("prepare 输出待补证草稿；缺少 Python 不伪造无候选", async t => {
  const f = await fixture(t);
  const prepared = await prepareBac({ planPath: f.planPath, sourceRoot: f.source, reportsRoot: f.reports, focusAreaId: f.item.focus_area_id, assignmentId: f.item.assignment_id, sessionId: "actual-session", runId: "draft-1" });
  const request = await readJson(prepared.request_path);
  assert.equal(request.api_catalog.apis[0].database_relevant, null);
  assert.equal(request.paths.coverage.status, "PARTIAL");
  await assert.rejects(compareBac({ requestPath: f.requestPath, reportsRoot: f.reports, environment: { ...process.env, AUDIT_BAC_PYTHON: join(f.root, "missing-python") } }));
  await assert.rejects(prepareBac({ planPath: f.planPath, sourceRoot: f.source, reportsRoot: f.source, focusAreaId: f.item.focus_area_id, assignmentId: f.item.assignment_id, sessionId: "actual-session", runId: "draft-2" }), /不得位于源码/);
});

test("候选完整接入三视角报告与本地工作包，再进入专项摘要", async t => {
  const f = await fixture(t), { run, output } = await compare(f);
  const reviewPath = join(f.root, "review-draft.json");
  await prepareReview({ runPath: output.run_path, output: reviewPath });
  const review = await readJson(reviewPath);
  review.decisions[0] = { bac_finding_id: run.result.findings[0].finding_id, disposition: "ACCEPTED", reason: "已逐项检查示例路径与控制。", finding: reviewedFinding(f, run) };
  await writeJson(reviewPath, review);
  const delivery = await reviewBac({ runPath: output.run_path, reviewPath, reportsRoot: f.reports });
  assert.deepEqual(await reviewBac({ runPath: output.run_path, reviewPath, reportsRoot: f.reports }), delivery);
  const checked = await validateBacAttachment({ reportsRoot: f.reports, attachment: delivery.attachment, item: f.item, auditId: run.audit_id, findings: delivery.findings, sessionId: run.producer.agent_session_id });
  assert.equal(checked.accepted, 1);
  await assert.rejects(validateBacAttachment({ reportsRoot: f.reports, attachment: delivery.attachment, item: f.item, auditId: run.audit_id, findings: [], sessionId: run.producer.agent_session_id }));
  const reports = [];
  for (const lens of f.item.required_lenses) {
    const report = { audit_id: run.audit_id, scope_digest: run.scope_digest, focus_area_id: run.focus_area_id, agent_name: run.producer.agent_name, agent_session_id: run.producer.agent_session_id,
      audit_strategy: lens, discovery_track: "coverage", scope: { focus_assignment_id: run.assignment_id }, findings: lens === "control-driven" ? delivery.findings : [],
      ...(lens === "control-driven" ? { bac_analysis: delivery.attachment } : {}) };
    const path = `${lens}.json`; await writeJson(join(f.reports, path), report);
    reports.push({ lens, path, sha256: sha256(await readFile(join(f.reports, path))) });
  }
  const packet = await validatePacketReports({ reportsRoot: f.reports, auditId: run.audit_id, item: f.item, reports });
  assert.equal(packet.bac_analysis.accepted, 1);
  const todoPath = join(f.root, "todo.json");
  const initialized = await initializeAuditTodo({ todoPath, auditId: run.audit_id, planPath: f.planPath });
  assert.equal(initialized.todo.items[0].bac_analysis.contract_version, BAC_CONTRACT);
  const claimed = await claimAuditTodo({ todoPath, packetLimit: 1, itemsPerPacket: 1 });
  // The exact handoff API is exercised below after writing its normal report bindings.
  const todo = await readJson(todoPath), active = todo.packets.find(row => row.status === "RUNNING");
  assert.ok(active && claimed);
  const handoff = { schema_version: 1, audit_id: run.audit_id, packet_id: active.packet_id, results: [{ item_id: todo.items[0].item_id, status: "DONE", reports }] };
  const handoffPath = join(f.reports, "handoff.json"); await writeJson(handoffPath, handoff);
  await completeAuditTodoPacket({ todoPath, packetId: active.packet_id, handoffPath, reportsRoot: f.reports });
  const summary = await buildLocalAuditSummary({ auditId: run.audit_id, planPath: f.planPath, todoPath, reportsRoot: f.reports });
  assert.equal(summary.bac_analysis.counts.accepted, 1);
  assert.deepEqual(validateBacSummary(summary.bac_analysis), []);
  assert.match(renderBacSummary(summary.bac_analysis).join("\n"), /越权专项分析/);
  // Finalization must not silently accept a missing BAC report model.
  await assert.rejects(verifyBacFinalReport({ audit: { id: run.audit_id, bac_analysis: bacSelection(), todo_path: todoPath }, reportsRoot: f.reports }));
});

test("缺口可交付；不适用必须有冻结源码证据", async t => {
  const f = await fixture(t), context = { reportsRoot: f.reports, item: f.item, auditId: f.plan.audit_id, sessionId: f.request.producer.agent_session_id };
  const gap = await validateBacAttachment({ ...context, attachment: { contract_version: BAC_CONTRACT, status: "GAP", reason: "自定义框架源码缺失。" } });
  assert.equal(gap.status, "GAP");
  const attachment = { contract_version: BAC_CONTRACT, status: "NOT_APPLICABLE", reason: "此项示例仅用于不适用附件契约测试。", plan_path: f.planPath, source_root: f.source, evidence: [f.evidence()] };
  assert.equal((await validateBacAttachment({ ...context, attachment })).status, "NOT_APPLICABLE");
  await assert.rejects(validateBacAttachment({ ...context, attachment: { ...attachment, evidence: [] } }));
  attachment.evidence[0].locator.source_digest = "c".repeat(64);
  await assert.rejects(validateBacAttachment({ ...context, attachment }));
});

test("冻结专项不能从任务清单删除；历史和关闭模式保持原要求", async t => {
  const f = await fixture(t), todoPath = join(f.root, "todo.json");
  const { todo } = await initializeAuditTodo({ todoPath, auditId: f.plan.audit_id, planPath: f.planPath });
  delete todo.items[0].bac_analysis; await writeJson(todoPath, todo);
  const check = await inspectFocusAreaCoverage({ todoPath, reportsRoot: f.reports });
  assert.ok(check.issues.some(issue => issue.includes("越权专项分派")));
  const historical = structuredClone(f.plan); delete historical.bac_analysis;
  assert.equal(bacForUnit(historical, historical.coverage_units[0]), null);
  historical.bac_analysis = bacSelection("off");
  assert.equal(bacForUnit(historical, historical.coverage_units[0]), null);
  assert.equal(await verifyBacFinalReport({ audit: {}, reportsRoot: f.reports }), true);
});

test("封存结果可重算，篡改计数或路径不能冒充相同差分", async t => {
  const f = await fixture(t), { output, run } = await compare(f);
  const directory = join(f.reports, "bac", f.plan.audit_id, "runs", "run-1");
  const validator = fileURLToPath(new URL("../skills/common-subagent/detect-bac-risks/scripts/validate_bac_findings.py", import.meta.url));
  const args = ["-I", "-B", "-X", "utf8", validator, "--acp", join(directory, "acp.json"), "--paths", join(directory, "paths.json"), "--api-catalog", join(directory, "apis.json"), "--findings", output.run_path];
  const python = process.env.AUDIT_BAC_PYTHON || (process.platform === "win32" ? "python" : "python3");
  const execute = promisify(execFile);
  const result = await execute(python, args, { encoding: "utf8", timeout: 30_000 });
  assert.equal(JSON.parse(result.stdout).valid, true);
  run.result.summary.matched_paths = 99;
  assert.throws(() => validateComparison(run.result, run.input));
  await writeJson(output.run_path, seal(run));
  await assert.rejects(execute(python, args, { encoding: "utf8", timeout: 30_000 }));
});

test("制品子目录链接不得把输出写入源码", async t => {
  const f = await fixture(t);
  await symlink(f.source, join(f.reports, "bac"), process.platform === "win32" ? "junction" : "dir");
  await assert.rejects(compareBac({ requestPath: f.requestPath, reportsRoot: f.reports }), /符号链接/);
});

test("摘要保留模型外项、跨包策略冲突与拒收缺口", () => {
  const row = { focus_area_id: "FA-1", assignment_id: "a", status: "COMPLETE", candidates: 1, accepted: 0, gaps: [], policy_bindings: [{ D: "db.orders", O: "READ", R: "MEMBER", AC: "VAC" }] };
  const summary = buildBacSummary([row, { ...structuredClone(row), focus_area_id: "FA-2", policy_bindings: [{ ...row.policy_bindings[0], AC: "VAC+HAC" }] }]);
  assert.equal(summary.status, "PARTIAL"); assert.match(summary.gaps[0], /ACP_CONFLICT/);
  assert.deepEqual(validateBacSummary(summary), []);
  summary.counts.accepted = 99; assert.ok(validateBacSummary(summary).length);
});

test("差分摘要、角色、主 check 与输出绑定不能伪造", async t => {
  const f = await fixture(t), { run } = await compare(f);
  const badResult = structuredClone(run.result); badResult.path_results = [];
  assert.throws(() => validateComparison(badResult, run.input));
  const review = { contract_version: BAC_CONTRACT, run_digest: run.artifact_digest, audit_id: run.audit_id, scope_digest: run.scope_digest, producer: run.producer,
    decisions: [{ bac_finding_id: run.result.findings[0].finding_id, disposition: "ACCEPTED", reason: "检查完成。", finding: reviewedFinding(f, run) }] };
  for (const edit of [r => r.decisions = [], r => r.decisions[0].finding.routing.primary_check_id = "invented", r => r.decisions[0].finding.state = "SUPPORTED_STATIC", r => r.decisions[0].finding.bac_source.run_digest = "b".repeat(64)]) {
    const changed = structuredClone(review); edit(changed); assert.throws(() => validateReview(changed, run, f.plan));
  }
  const rejected = structuredClone(review);
  delete rejected.decisions[0].finding;
  rejected.decisions[0].disposition = "REJECTED";
  assert.throws(() => validateReview(rejected, run, f.plan));
  rejected.decisions[0].evidence = [f.evidence("本例仅检查反证绑定格式。")];
  assert.equal(validateReview(rejected, run, f.plan), rejected);
  assert.equal(objectDigest({ a: 1, b: 2 }), objectDigest({ b: 2, a: 1 }));
  assert.equal(seal(run).artifact_digest, run.artifact_digest);
});

test("历史 stage registry 不变；新增策略模式有显式版本与角色登记", async () => {
  const registry = await readJson(new URL("../skills/common-subagent/audit-artifact-management/contracts/stage-agent-contracts.json", import.meta.url));
  const roles = await readJson(new URL("../agent-manifest/roles.json", import.meta.url));
  assert.equal(bacStageRegistry(registry, "off"), registry);
  assert.deepEqual(validateStageContractRegistry(registry, roles), []);
  const projected = bacStageRegistry(registry, "auto");
  assert.deepEqual(validateStageContractRegistry(projected, roles), []);
  assert.equal(projected.contracts.length, registry.contracts.length + 1);
  for (const mode of ["off", "auto"]) {
    const runtime = runtimeStageRegistry(registry, "runtime-testing.v1", mode);
    assert.deepEqual(validateStageContractRegistry(runtime, roles), []);
    assert.deepEqual(runtimeStageRegistry(runtime, "runtime-testing.v1", mode), runtime);
  }
  assert.throws(() => bacSelection("invalid"));
});
