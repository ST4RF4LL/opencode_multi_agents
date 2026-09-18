import assert from "node:assert/strict";
import { test } from "node:test";
import { exampleFinding, exampleDossier, SHA } from "./fixtures/report-details.mjs";
import { validateFinding, findingObjectDigest } from "../skills/common-subagent/finding-evidence-contract/scripts/finding-contract.mjs";
import { validateFindingReportDetails } from "../skills/common-subagent/finding-evidence-contract/scripts/finding-report-details.mjs";
import { validateFindingDossier } from "../skills/common-subagent/audit-coverage-accounting/scripts/report-dossier.mjs";
import { renderFindingDossier, renderChainDetails, runtimeDetail } from "../skills/common-subagent/audit-coverage-accounting/scripts/render-report-dossier.mjs";
import { buildStaticFactPacket } from "../skills/vulnerability-validator-subagent/vulnerability-validation/scripts/static-fact-packet.mjs";

test("新候选契约强制内容，历史候选保持兼容", () => {
  const finding = exampleFinding();
  assert.deepEqual(validateFindingReportDetails(finding, { required: true }), []);
  assert.deepEqual(validateFinding(finding), []);
  const originalDigest = findingObjectDigest(finding);
  delete finding.report_details;
  assert.deepEqual(validateFinding(finding), []);
  assert.ok(validateFinding(finding, { requireReportDetails: true }).includes("finding-report-details-missing"));
  assert.notEqual(findingObjectDigest(finding), originalDigest);
});

test("拒绝无效事实索引、缺失成因、伪装执行和不完整回归标准", () => {
  const mutations = [
    [value => value.report_details.path[1].evidence_fact_indexes = [99], "finding-report-path-incomplete"],
    [value => value.report_details.root_cause.actual_behavior = "", "finding-report-root-cause-incomplete"],
    [value => value.report_details.reproduction.execution_status = "COMPLETED", "finding-report-reproduction-plan-invalid"],
    [value => value.report_details.regression_tests.pop(), "finding-report-regression-tests-incomplete"],
    [value => value.report_details.code_context.snippets[0].evidence_fact_index = -1, "finding-report-code-context-invalid"],
    [value => value.title = "English title", "finding-report-title-chinese-required"],
    [value => value.report_details.contract = "finding-details.v99", "finding-report-details-contract-invalid"],
  ];
  for (const [mutate, error] of mutations) {
    const finding = exampleFinding(); mutate(finding);
    assert.ok(validateFindingReportDetails(finding).includes(error), error);
  }
});

test("代码上下文不可获取时必须写原因并保留为交付缺口", () => {
  const finding = exampleFinding();
  finding.report_details.code_context = { state: "UNAVAILABLE", snippets: [], reason: "依赖只提供摘要，无法获得源码片段。" };
  assert.deepEqual(validateFindingReportDetails(finding), []);
  const { row } = exampleDossier({ finding });
  assert.match(row.dossier.missing_sections[0], /无法获得源码片段/);
  assert.deepEqual(validateFindingDossier(row), []);
  row.dossier.missing_sections = [];
  assert.ok(validateFindingDossier(row).includes("final-report-dossier-gaps-mismatch"));
  finding.report_details.code_context.reason = "";
  assert.ok(validateFindingReportDetails(finding).includes("finding-report-code-context-invalid"));
});

test("事实包、最终档案和正文保留原始事实与完整复核判断", () => {
  const { row, candidate, decision, roles } = exampleDossier();
  assert.deepEqual(validateFindingDossier(row), []);
  const packet = buildStaticFactPacket({ candidate, decision, auditId: candidate.finding.audit_id, scopeDigest: SHA, round: 1, candidateDigest: SHA, adjudicationDigest: SHA });
  assert.deepEqual(packet.report_details, candidate.finding.report_details);
  assert.deepEqual(row.dossier.finding, candidate.finding);
  assert.deepEqual(row.dossier.adjudication, decision);
  assert.deepEqual(row.dossier.origins.source_reports, candidate.source_reports);
  const markdown = renderFindingDossier(row).join("\n");
  for (const expected of [decision.semantic_proof.path.steps[0], decision.counterclaim.claim, decision.attack_surface_review.limitations[0], row.cvss.rationale,
    ...roles.map(role => role.manifest.findings[0].reasoning), "复现设计（未执行）", "已跳过", "未提供动态测试环境"]) assert.ok(markdown.includes(expected), expected);
  candidate.finding.report_details.root_cause.summary = "修改原始对象。";
  assert.notEqual(row.dossier.finding.report_details.root_cause.summary, candidate.finding.report_details.root_cause.summary);
  row.evidence_facts = [];
  assert.ok(validateFindingDossier(row).includes("final-report-dossier-evidence_facts-mismatch"));
});

test("运行证据仅绑定当前候选摘要与关联假设，保留观察、证明及清理细节", () => {
  const finding = exampleFinding(), findingDigest = findingObjectDigest(finding);
  const evidence = { status: "CLOSED", packets: [
    { id: "contact", phase: "CONTACT", execution_status: "COMPLETED", result: { observations: ["环境基线观察。"] } },
    { id: "explore", phase: "EXPLORE", hypothesis_id: "hyp-current", result: { observations: ["中期观察。"], evidence_ids: ["explore.action-1"] } },
    { id: "confirm", phase: "CONFIRM", finding_id: finding.finding_id, finding_object_digest: findingDigest, hypothesis_id: "hyp-current", execution_status: "COMPLETED", outcome: "SUPPORTED", cleanup_status: "FAILED", input_digest: SHA, result_digest: SHA,
      result: { summary: "仅用于格式测试的观察摘要。", observations: ["测试账户边界检查记录。"], evidence_ids: ["confirm.action-1"], proof: { state: "observed", marker: "synthetic-marker" }, changes: [{ marker: "synthetic-marker", resource: "测试资源", cleanup_status: "FAILED", reason: "清理入口返回失败，需要人工移除。" }], gaps: ["只验证一个测试资源。"] } },
    { id: "stale", phase: "CONFIRM", finding_id: finding.finding_id, finding_object_digest: "b".repeat(64), result: { evidence_ids: ["stale.action-1"] } },
  ], evidence_bindings: ["explore.action-1", "confirm.action-1", "stale.action-1"].map(id => ({ id, path: `evidence/${id}.json`, sha256: SHA })) };
  const { row } = exampleDossier({ finding, runtimeEvidence: evidence });
  assert.deepEqual(row.dossier.runtime.packets.map(packet => packet.id), ["explore", "confirm"]);
  assert.deepEqual(row.dossier.runtime.evidence_bindings.map(item => item.id), ["explore.action-1", "confirm.action-1"]);
  const markdown = renderFindingDossier(row).join("\n");
  for (const expected of ["中期观察", "测试账户边界检查记录", "synthetic-marker", "清理入口返回失败", "只验证一个测试资源", "evidence/confirm.action-1.json"]) assert.ok(markdown.includes(expected), expected);
  assert.ok(!markdown.includes("stale.action-1"));
  assert.ok(runtimeDetail({ ...evidence, protocol: "runtime-testing.v1" }).join("\n").includes("环境基线观察"));
});

test("历史无详细内容和排除项仍展开证据与缺口，不补造复现", () => {
  const finding = exampleFinding(); delete finding.report_details;
  const { row } = exampleDossier({ finding, integrated: false, runtimeEvidence: { results: [], evidence_bindings: [] } });
  row.state = "INCONCLUSIVE";
  row.validation.final_verdict = "INCONCLUSIVE";
  row.dossier.reviews.find(review => review.role === "MODERATOR").review.verdict = "INCONCLUSIVE";
  assert.deepEqual(validateFindingDossier(row), []);
  const markdown = renderFindingDossier(row, { excluded: true }).join("\n");
  assert.match(markdown, /候选处置/); assert.match(markdown, /证据不足/);
  assert.match(markdown, /上游未提供可复核的复现步骤/);
  assert.match(markdown, /上游候选未提供版本化/);
  assert.match(markdown, /没有运行验证记录/);
});

test("代码片段中的 Markdown 围栏不会截断代码证据", () => {
  const finding = exampleFinding(); finding.report_details.code_context.snippets[0].text = "// ```\nconst resource = 'example';";
  const markdown = renderFindingDossier(exampleDossier({ finding }).row).join("\n");
  assert.match(markdown, /````javascript\n\/\/ ```\nconst resource = 'example';\n````/);
});

test("攻击链展示每一步、连接条件与阻断缺口", () => {
  const markdown = renderChainDetails({ chain_id: "CHAIN-EXAMPLE", assessment_state: "CONDITIONAL", steps: [{ step_id: "S1", evidence_state: "SUPPORTED_STATIC", claim: "示例链第一步。", evidence_refs: ["FIND-EXAMPLE-001"], blocking_gap_ids: ["G1"] }],
    transitions: [{ transition_id: "T1", requires: ["S1"], produces: ["S2"], status: "UNRESOLVED", evidence_refs: ["FIND-EXAMPLE-001"] }], gaps: [{ gap_id: "G1", reason: "第二步权限前提尚未证明。" }] }).join("\n");
  for (const expected of ["示例链第一步", "S1 → S2", "第二步权限前提尚未证明", "条件未满足"]) assert.ok(markdown.includes(expected), expected);
});
