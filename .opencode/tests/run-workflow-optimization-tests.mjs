import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PACKET_REPORT_CONTRACT, PACKET_LENSES, itemReportPaths, validatePacketReports } from "../scripts/packet-reports.mjs";
import { initializeAuditTodo, claimAuditTodo, completeAuditTodoPacket, readAuditTodo } from "../scripts/audit-todo-core.mjs";
import { buildLocalAuditSummary } from "../scripts/build-local-audit-summary.mjs";
import { AI_COVERAGE_POLICY, buildAiRouting, aiRequired, validateAiRouting } from "../skills/common-subagent/audit-coverage-accounting/scripts/ai-coverage-routing.mjs";
import { activeDomains, interfaceDomains, validateFocusAreaPartition } from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-v2-common.mjs";
import { buildStaticFactPacket, writeStaticFactPacket, validateBoundFactPackets } from "../skills/vulnerability-validator-subagent/vulnerability-validation/scripts/static-fact-packet.mjs";
import { truthValidationArtifactDigest, validateStaticRoleReview } from "../skills/vulnerability-validator-subagent/vulnerability-validation/scripts/truth-validation-contract.mjs";

const hash = value => createHash("sha256").update(value).digest("hex");
const scope = { audit_id: "workflow-test", scope_digest: "a".repeat(64), policy: { ai_coverage: AI_COVERAGE_POLICY }, files: Array.from({ length: 30 }, (_, i) => ({ file_id: `f${i}`, path: `src/F${i}.java`, sha256: hash(`source${i}`), review_required: true, owner_agent: "java-source-auditor" })) };
const decisions = scope.files.map(file => ({ file_id: file.file_id, state: "NOT_APPLICABLE", reason: "已检查该文件及依赖，无 AI 特有入口。", evidence_refs: [file.path], depends_on_file_ids: [] }));
scope.ai_routing = buildAiRouting(scope, decisions);
assert.deepEqual(validateAiRouting(scope), []);
assert.equal(scope.ai_routing.required_file_ids.length, 3, "negative samples replace full second coverage");
assert.equal(scope.ai_routing.excluded_file_ids.length, 27);
const excluded = scope.files.find(file => scope.ai_routing.excluded_file_ids.includes(file.file_id));
assert.equal(aiRequired(scope, excluded), false);
assert.deepEqual(interfaceDomains({ file_id: excluded.file_id, owner_agent: excluded.owner_agent }, scope), ["java"]);
assert.equal(aiRequired({ files: scope.files }, excluded), true, "historical policy remains full coverage");
const edited = structuredClone(decisions);
edited[0].state = "RELEVANT"; edited[0].depends_on_file_ids = ["f1"];
edited[2].depends_on_file_ids = ["f1"]; edited[3].state = "UNKNOWN";
const routed = { ...scope, ai_routing: buildAiRouting(scope, edited) };
for (const id of ["f0", "f1", "f2", "f3"]) assert.ok(routed.ai_routing.required_file_ids.includes(id));
assert.deepEqual(routed.ai_routing.unknown_file_ids, ["f3"]);
assert.ok(activeDomains(routed).includes("ai"));
const tampered = structuredClone(routed); tampered.ai_routing.required_file_ids = [];
assert.ok(validateAiRouting(tampered).length);
assert.throws(() => buildAiRouting(scope, decisions.slice(1)), /逐文件/);
assert.throws(() => buildAiRouting(scope, [{ ...decisions[0], evidence_refs: ["absent.java"] }, ...decisions.slice(1)]), /冻结范围/);
const focus = { focus_areas: [{ focus_area_id: "focus", assignments: [
  { assignment_id: "java", language: "java", agent_name: "java-source-auditor", file_function_domain: "base", catalog_domain: "java", file_ids: scope.files.map(file => file.file_id), function_ids: [], catalog_ids: [] },
  { assignment_id: "ai", language: "ai", agent_name: "ai-security-auditor", file_function_domain: "ai", catalog_domain: "ai", file_ids: scope.ai_routing.required_file_ids, function_ids: [], catalog_ids: [] },
] }] };
assert.deepEqual(validateFocusAreaPartition({ scope, functionManifests: [], catalog: { entries: [] }, focusAreas: focus }), []);

const root = await mkdtemp(join(tmpdir(), "workflow-optimization-"));
try {
  const reportsRoot = join(root, "reports"); await mkdir(reportsRoot);
  const planPath = join(root, "plan.json"), todoPath = join(root, "todo.json");
  const unit = { unit_id: "unit", focus_area_id: "focus", assignment_id: "assignment", domain: "java", agent_name: "java-source-auditor", required_lenses: PACKET_LENSES, check_ids: ["check"] };
  await writeFile(planPath, JSON.stringify({ audit_id: scope.audit_id, scope_digest: scope.scope_digest, packet_report_contract: PACKET_REPORT_CONTRACT, ai_routing_unknown_file_ids: ["f3"], coverage_units: [unit] }));
  await initializeAuditTodo({ todoPath, auditId: scope.audit_id, planPath });
  const packet = (await claimAuditTodo({ todoPath })).packets[0];
  const item = (await readAuditTodo(todoPath)).items[0];
  const reports = [];
  for (const lens of PACKET_LENSES) {
    const content = JSON.stringify({ audit_id: scope.audit_id, scope_digest: scope.scope_digest, agent_name: unit.agent_name, agent_session_id: "single-session", focus_area_id: "focus", discovery_track: "coverage", audit_strategy: lens, scope: { focus_assignment_id: "assignment" }, findings: [{ finding_id: `finding-${lens}` }] });
    const path = lens + ".audit-report.json"; await writeFile(join(reportsRoot, path), content);
    reports.push({ lens, path, sha256: hash(content) });
  }
  await assert.rejects(validatePacketReports({ reportsRoot, auditId: scope.audit_id, item, reports: reports.slice(1) }), /三个/);
  await assert.rejects(validatePacketReports({ reportsRoot, auditId: scope.audit_id, item, reports: [{ ...reports[0], sha256: "0".repeat(64) }, ...reports.slice(1)] }), /摘要/);
  const original = await readFile(join(reportsRoot, reports[0].path), "utf8");
  const otherSession = JSON.stringify({ ...JSON.parse(original), agent_session_id: "other-session" });
  await writeFile(join(reportsRoot, reports[0].path), otherSession);
  await assert.rejects(validatePacketReports({ reportsRoot, auditId: scope.audit_id, item, reports: [{ ...reports[0], sha256: hash(otherSession) }, ...reports.slice(1)] }), /同一次/);
  await writeFile(join(reportsRoot, reports[0].path), original);
  const handoffPath = join(reportsRoot, "handoff.json");
  const handoff = { schema_version: 1, audit_id: scope.audit_id, packet_id: packet.packet_id, results: [{ item_id: item.item_id, status: "DONE", reports, finding_ids: ["fabricated"] }] };
  await writeFile(handoffPath, JSON.stringify(handoff));
  const completed = await completeAuditTodoPacket({ todoPath, packetId: packet.packet_id, handoffPath, reportsRoot });
  assert.equal(completed.summary.done, 1);
  const done = (await readAuditTodo(todoPath)).items[0];
  assert.equal(itemReportPaths(done).length, 3);
  assert.equal(done.finding_ids.includes("fabricated"), false);
  const summary = await buildLocalAuditSummary({ auditId: scope.audit_id, planPath, todoPath, reportsRoot });
  assert.equal(summary.coverage_status, "PARTIAL", "AI unknown cannot disappear behind DONE tasks");
  assert.equal(summary.residual_gaps.length, 1);
  await writeFile(join(reportsRoot, reports[0].path), "changed");
  await assert.rejects(buildLocalAuditSummary({ auditId: scope.audit_id, planPath, todoPath, reportsRoot }), /摘要/);

  const candidate = { finding_id: "finding", finding_object_digest: "b".repeat(64), finding: { evidence: { facts: [{ kind: "source", confidence: "high" }, { kind: "sink", confidence: "high" }] }, uncertainty: { level: "low" }, contradictions: [], guards: [], attack_surface: { target_reach: { state: "SINGLE_OBJECT" } } } };
  const decision = { semantic_proof: { path: { state: "PROVEN" } }, guards: [], contradiction_refs: [], blocking_questions: [] };
  const input = { candidate, decision, auditId: scope.audit_id, scopeDigest: scope.scope_digest, round: 1, candidateDigest: "c".repeat(64), adjudicationDigest: "d".repeat(64) };
  const facts = buildStaticFactPacket(input);
  assert.equal(facts.minimum_review_mode, "TARGETED");
  const full = buildStaticFactPacket({ ...input, decision: { ...decision, blocking_questions: ["版本待确认"] } });
  assert.equal(full.minimum_review_mode, "FULL");
  const binding = await writeStaticFactPacket(root, full);
  assert.deepEqual(await writeStaticFactPacket(root, full), binding, "same content is idempotent");
  const intake = { audit_id: scope.audit_id, scope_digest: scope.scope_digest, round: 1, artifact_digest: "e".repeat(64), findings: [{ finding_id: "finding", finding_object_digest: candidate.finding_object_digest, ...binding }] };
  await validateBoundFactPackets(root, intake);
  const quick = { artifact_digest: "f".repeat(64), results: [{ finding_id: "finding", status: "SKIPPED" }] };
  const review = { schema_version: 1, artifact_type: "static-truth-review", audit_id: scope.audit_id, round: 1, role: "AFFIRMATIVE", execution_status: "COMPLETE", agent_session_id: "affirmative", intake_digest: intake.artifact_digest, quick_result_digest: quick.artifact_digest, reviewed_finding_ids: ["finding"], findings: [{ finding_id: "finding", verdict: "INCONCLUSIVE", claims: ["证据仍有缺口。"], evidence_refs: ["src/F0.java"], reasoning: "已核查关键事实，版本仍需确认。", gaps: ["版本未确认。"], fact_packet_digest: binding.fact_packet_digest, review_mode: "FULL", checked_evidence_refs: ["src/F0.java"] }] };
  review.artifact_digest = truthValidationArtifactDigest(review);
  assert.deepEqual(validateStaticRoleReview(review, { intake, quickResultSet: quick, role: "AFFIRMATIVE" }), []);
  review.findings[0].review_mode = "TARGETED"; review.artifact_digest = truthValidationArtifactDigest(review);
  assert.ok(validateStaticRoleReview(review, { intake, quickResultSet: quick, role: "AFFIRMATIVE" }).some(error => error.includes("fact-review-binding")));
  await writeFile(join(root, binding.fact_packet_path), JSON.stringify({ ...full, facts: [] }));
  await assert.rejects(validateBoundFactPackets(root, intake), /摘要/);
} finally { await rm(root, { recursive: true, force: true }); }
process.stdout.write(JSON.stringify({ complete: true, contract: "workflow-optimizations-1-4" }) + "\n");
