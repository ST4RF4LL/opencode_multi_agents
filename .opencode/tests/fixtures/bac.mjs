// Offline fixture: no application is built, launched, or contacted.
import { mkdtemp, mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BAC_CONTRACT, bacForUnit, sha256 } from "../../lib/bac/contract.mjs";
import { objectDigest as planDigest } from "../../skills/common-subagent/audit-coverage-accounting/scripts/coverage-v2-common.mjs";
import { exampleFinding } from "./report-details.mjs";

export const readJson = path => readFile(path, "utf8").then(JSON.parse);
export const writeJson = (path, value) => writeFile(path, `${JSON.stringify(value, null, 2)}\n`);

export async function bacFixture() {
  const root = await mkdtemp(join(tmpdir(), "bac-中文 路径-")), source = join(root, "source"), reports = join(root, "reports");
  await mkdir(join(source, "src"), { recursive: true }); await mkdir(reports);
  const code = "class OrderService {\n  Object get(String id) {\n    requireMember();\n    return mapper.select(id);\n  }\n}\n";
  const file = "src/OrderService.java", digest = sha256(code), scope = sha256("offline-bac-scope");
  await writeFile(join(source, file), code);
  const locator = line => ({ file, line_start: line, source_digest: digest });
  const evidence = (claim = "示例中查阅了完整资源读取路径。", kind = "control") => ({ kind, claim, locator: locator(4) });
  const check = { check_id: "check-bac-owner", focus_area_id: "FA-ORDER", domain: "java", lens: "control-driven", dimensions: ["D3", "D9"], vulnerability_type_id: "JW-ACCESS-01", required_interface_ids: ["interface-order"] };
  const unit = { unit_id: "unit-order", assignment_id: "assign-order", focus_area_id: "FA-ORDER", domain: "java", agent_name: "java-source-auditor",
    check_ids: [check.check_id], required_lenses: ["sink-driven", "control-driven", "config-driven"], required_source_set_id: "set-order", required_check_count: 1 };
  const plan = { schema_version: 3, audit_id: "audit-bac-fixture", scope_digest: scope, packet_report_contract: "tri-lens-v2", finding_detail_contract: "finding-details.v1",
    bac_analysis: { contract_version: BAC_CONTRACT, mode: "auto" }, source_index: [{ file_id: "file-order", path: file, sha256: digest, type: "file", owner_agent: unit.agent_name }],
    coverage_units: [unit], checks: [check], interface_index: [{ interface_id: "interface-order", file_id: "file-order", direction: "ingress", kind: "http", protocol: "http", operation: "GET", address: "/orders/{id}", line_start: 2 }],
    source_sets: [{ source_set_id: "set-order", file_ids: ["file-order"] }] };
  plan.manifest_digest = planDigest(plan);
  const planPath = join(root, "plan.json"); await writeJson(planPath, plan);
  const producer = { agent_name: unit.agent_name, agent_session_id: "source-session-1" };
  const repository = { root: source, scope_digest: scope, revision: "fixture-commit" };
  const policy = { D: "shop.orders", O: "READ", R: "MEMBER", AC: "VAC+HAC" };
  const control = (names, effective) => ({ ...Object.fromEntries(names.map(name => [name, effective])), evidence: [evidence()] });
  const vac = control(["observed", "trusted_identity", "role_match", "dominates_sink", "fail_closed"], true);
  const hac = control(["observed", "trusted_principal", "owner_relation_enforced", "dominates_sink", "fail_closed"], false);
  const request = { contract_version: BAC_CONTRACT, audit_id: plan.audit_id, scope_digest: scope, focus_area_id: unit.focus_area_id, assignment_id: unit.assignment_id,
    producer, run_id: "run-1", plan_path: planPath, source_root: source,
    resource_role_catalog: { resources: [{ D: policy.D, evidence: [evidence()] }], roles: [{ R: policy.R, evidence: [evidence()] }], aliases: [], known_gaps: [] },
    acp: { repository, producer: { agent_name: "security-threat-modeler", agent_session_id: "policy-session-1" }, coverage: { status: "COMPLETE", evidence: [evidence()], known_gaps: [] },
      quadruples: [{ tuple: policy, confidence: .96, evidence: [evidence("同资源显式策略要求直接所有者约束。", "policy")], inference_basis: "受控 fixture 的显式策略。" }], unresolved: [], out_of_model: [], limitations: [] },
    paths: { repository, producer, coverage: { status: "COMPLETE", evidence: [evidence()], known_gaps: [] }, paths: [{ path_id: "path-order", api_id: "interface-order",
      entrypoint: { interface_type: "EXTERNAL", operation: "GET /orders/{id}", location: locator(2) }, sink: { D: policy.D, O: "READ", location: locator(4), symbol: "mapper.select" },
      policy_binding: policy, policy_binding_evidence: [evidence()], caller_context: { principal: "已登录测试用户", roles: ["MEMBER"] },
      reachability: { status: "REACHABLE", evidence: [evidence()] }, input_flow: { attacker_controllable: true, evidence: [evidence()] }, implemented_controls: { vac, hac },
      call_chain: [{ symbol: "OrderService.get → mapper.select", evidence: [evidence()] }], coverage: "COMPLETE", known_gaps: [], evidence: [evidence()] }], limitations: [] },
    api_catalog: { repository, coverage: { status: "COMPLETE", evidence: [evidence()], known_gaps: [] }, apis: [{ api_id: "interface-order", database_relevant: true }] } };
  const requestPath = join(root, "request.json"); await writeJson(requestPath, request);
  const item = { ...unit, scope_digest: scope, bac_analysis: bacForUnit(plan, unit), report_contract: "tri-lens-v2", finding_detail_contract: "finding-details.v1" };
  return { root, source, reports, planPath, plan, requestPath, request, locator, evidence, item };
}

export function reviewedFinding(fixture, run) {
  const finding = exampleFinding();
  finding.audit_id = run.audit_id; finding.scope_digest = run.scope_digest; finding.finding_id = "FIND-BAC-ORDER";
  finding.classification = { vulnerability_type_id: "JW-ACCESS-01", origin_lens: "control-driven", discovery_track: "coverage", dimension_claims: [{ dimension: "D3", rationale: "示例路径未约束直接资源所有者。" }] };
  finding.routing = { focus_area_id: run.focus_area_id, primary_check_id: "check-bac-owner", domain: "java", threat_ids: ["T-ORDER"] };
  finding.locations.primary = fixture.locator(4);
  finding.evidence.facts.forEach((fact, i) => { fact.locator = fixture.locator(i ? 4 : 2); fact.source_digest = fact.locator.source_digest; });
  finding.provenance.source_report_sha256 = run.artifact_digest;
  finding.bac_source = { run_digest: run.artifact_digest, candidate_id: run.result.findings[0].finding_id };
  finding.report_details.code_context.snippets[0].language = "java";
  finding.report_details.code_context.snippets[0].text = "return mapper.select(id);";
  return finding;
}
