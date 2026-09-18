// Synthetic format fixture: no target was contacted and no vulnerability was tested.
import { findingObjectDigest } from "../../skills/common-subagent/finding-evidence-contract/scripts/finding-contract.mjs";
import { buildFindingDossier } from "../../skills/common-subagent/audit-coverage-accounting/scripts/report-dossier.mjs";

export const SHA = "a".repeat(64);
export const binding = (artifact, json_pointer = "/findings/0") => ({ artifact: `reports/example/${artifact}.json`, digest: SHA, json_pointer });
export function exampleFinding() {
  const locator = line => ({ file: "src/example-resource.js", line_start: line, source_digest: SHA });
  const assessment = (state, rationale) => ({ state, rationale, evidence_fact_indexes: [0, 1] });
  return {
    finding_schema_version: 2, finding_id: "FIND-EXAMPLE-001", audit_id: "audit-format-example", scope_digest: SHA, state: "CANDIDATE",
    title: "示例：资源读取缺少对象归属校验",
    classification: { vulnerability_type_id: "EXAMPLE-AUTHZ-01", origin_lens: "sink-driven", discovery_track: "coverage", dimension_claims: [{ dimension: "D2", rationale: "资源权限边界受到影响。" }] },
    routing: { focus_area_id: "FA-EXAMPLE", primary_check_id: "check-example", domain: "web", threat_ids: ["T-EXAMPLE"] },
    locations: { primary: locator(12) },
    evidence: { facts: [
      { kind: "source", claim: "请求参数决定待查询资源标识。", locator: locator(10), method: "manual-source", source_digest: SHA, confidence: "high" },
      { kind: "sink", claim: "查询后直接返回资源，当前路径未比较主体与资源归属。", locator: locator(12), method: "manual-source", source_digest: SHA, confidence: "high" },
    ] },
    reachability: { state: "static-reachable" }, attacker_influence: { state: "direct" },
    attack_surface: {
      schema_version: 1, in_scope: assessment("YES", "示例文件在审计范围内。"),
      exposure: { ...assessment("PUBLIC", "入口在应用路由中注册。"), surface: "资源读取入口" },
      vector: assessment("NETWORK", "外部请求可选择资源。"), auth_scope: assessment("AUTHENTICATED", "示例前置中间件只检查登录状态。"),
      preconditions: [{ precondition_id: "PRE-EXAMPLE", description: "两个测试账户拥有各自的独立测试资源。", feasibility: "UNPROVEN", evidence_fact_indexes: [] }],
      identities: { attacker: "测试账户乙", victim: "测试账户甲", effective_principal: "当前登录账户", evidence_fact_indexes: [0, 1] },
      boundary_crossing: { ...assessment("PROVEN", "资源选择未绑定当前主体。"), from: "当前账户的资源边界", to: "另一账户的资源边界" },
      impact: { types: ["CONFIDENTIALITY"], outcome: "可能读取另一测试账户的资源。", evidence_fact_indexes: [1] },
      target_reach: assessment("SINGLE_USER", "证据限于单项资源读取，未证明批量影响。"), controls: [], counterevidence: [],
      blindspots: ["没有动态环境，部署层拦截尚未验证。"], confidence: { level: "medium", rationale: "示例静态路径清楚，运行条件尚未核验。" },
    }, guards: [], contradictions: [], uncertainty: { level: "medium", assumptions: ["示例入口按记录中的中间件链部署。"] },
    severity: { rationale: "存在跨账户资源读取的静态风险。" }, remediation: { summary: "将主体和租户约束纳入查询与响应前的授权判断。" },
    provenance: { source_report_sha256: SHA },
    report_details: {
      contract: "finding-details.v1",
      root_cause: { summary: "资源读取路径只验证登录状态，未校验资源归属。", expected_behavior: "仅允许资源所有者或显式获授权主体读取。", actual_behavior: "查询使用外部资源标识，返回前没有主体与归属比较。" },
      code_context: { state: "RECORDED", snippets: [{ evidence_fact_index: 1, language: "javascript", text: "const item = repository.find(request.params.id);\nreturn item;", redacted: false }], reason: null },
      path: [{ description: "已登录请求提供资源标识。", evidence_fact_indexes: [0] }, { description: "查询结果未经过归属判断便返回调用者。", evidence_fact_indexes: [1] }],
      reproduction: { execution_status: "NOT_RUN", environment_requirements: "明确授权的本机隔离环境，具备两个测试账户。", preconditions: ["使用独立测试数据，已知各自资源归属。"],
        steps: ["记录账户甲读取自己测试资源的基线。", "用账户乙请求同一测试资源，对照响应。"], expected_secure_result: "账户乙被拒绝且响应不包含账户甲的数据。", expected_vulnerable_result: "账户乙收到仅应由账户甲访问的测试资源。" },
      remediation: { changes: [{ location: "资源查询与响应返回之间", action: "按当前主体和租户限制查询。", rationale: "将权限判断绑定到实际资源。" }], temporary_mitigations: ["限制受影响入口的访问范围。"], compatibility_notes: ["保留显式获授权的管理员路径。"] },
      regression_tests: [{ kind: "SECURITY", scenario: "非所有者读取另一账户的测试资源。", expected_result: "拒绝请求，响应不含资源内容。" }, { kind: "FUNCTIONAL", scenario: "所有者读取自己的测试资源。", expected_result: "正常返回合法资源。" }],
    },
  };
}

export function exampleDossier({ finding = exampleFinding(), runtimeEvidence = { status: "SKIPPED", reason: "未提供动态测试环境，已跳过。", packets: [], evidence_bindings: [] }, integrated = true } = {}) {
  const candidate = { finding_id: finding.finding_id, finding_object_digest: findingObjectDigest(finding), finding,
    artifact: { path: "reports/example/source.json", sha256: SHA }, source_reports: ["reports/example/web-source-auditor.json"] };
  const decision = { finding_id: finding.finding_id, finding_object_digest: candidate.finding_object_digest, state: "SUPPORTED_STATIC", decision_rationale: "示例源码支持权限判断缺失，动态条件保留为限制。",
    semantic_proof: { source_fact_indexes: [0], sink_or_config_fact_indexes: [1], framework: { component: "示例框架", version_or_commit: "example-revision", api_or_configuration: "repository.find", evidence: ["示例 API 只按资源标识查询，不附加主体过滤。"] },
      path: { state: "PROVEN", steps: ["独立追踪参数进入查询接口。", "独立检查响应前没有对象权限分支。"] }, security_effect: { state: "PROVEN", rationale: "当前示例路径可返回未按主体筛选的对象。" } },
    guards: ["local", "inherited", "global", "deployment"].map(scope => ({ scope, state: scope === "deployment" ? "NOT_APPLICABLE" : "ABSENT", effective_for_claim: false, rationale: scope === "deployment" ? "本例只评估源码授权约束，外部部署不纳入已证明范围。" : "示例检查范围内未找到对象权限防护。", evidence: ["示例保护检查记录。"] })),
    attack_surface_review: { disposition: "LIMITED", rationale: "静态路径已检查，部署假设未验证。", evidence: ["已复核入口、主体、资源和响应路径。"], limitations: ["不能宣称运行环境已复现。"] },
    counterclaim: { claim: "上层中间件可能已经校验资源归属。", outcome: "REFUTED", evidence: ["示例中间件只建立登录主体，不读取资源归属。"] }, contradiction_refs: [], blocking_questions: [],
  };
  const roles = ["AFFIRMATIVE", "NEGATIVE", "MODERATOR"].map(role => ({ role, artifact: `reports/example/${role}.json`, manifest: { agent_session_id: `example-${role}`, artifact_digest: SHA,
    findings: [{ finding_id: finding.finding_id, verdict: { AFFIRMATIVE: "PROVEN", NEGATIVE: "REFUTED", MODERATOR: "TRUE_POSITIVE" }[role], claims: ["示例对象授权路径需要补齐。"], evidence_refs: ["E0", "E1"], checked_evidence_refs: ["E0", "E1"],
      reasoning: ({ AFFIRMATIVE: "正方沿参数、查询、响应验证对象权限缺失。", NEGATIVE: "反方检查中间件和全局拦截，示例中没有足以推翻静态结论的证据。", MODERATOR: "裁定采纳静态结论，明确未取得动态复现证据。" })[role],
      gaps: ["运行条件尚未验证。"], review_mode: "FULL", fact_packet_digest: SHA,
      runtime_review: { evidence_validity: "NOT_APPLICABLE", packet_ids: [], reasoning: "没有动态环境，本次只复核静态证据。" } }],
  } }));
  const row = { finding_id: finding.finding_id, finding_object_digest: candidate.finding_object_digest, title: finding.title, vulnerability_type_id: finding.classification.vulnerability_type_id, domain: finding.routing.domain,
    state: "TRUE_POSITIVE", preliminary_state: decision.state, primary_location: finding.locations.primary, evidence_facts: finding.evidence.facts, remediation: finding.remediation, attack_surface: finding.attack_surface,
    source: binding("adjudication", "/decisions/0"), validation: { route: "STATIC_THREE_PARTY", final_verdict: "TRUE_POSITIVE", rationale: "示例通过独立三方静态复核，运行环境仍未知。", source: binding("routing") },
    cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", base_score: 6.5, severity: "MEDIUM", rationale: "示例假设已登录账户能跨账户读取敏感资源。", assumptions: ["影响仅限当前示例资源的机密性。"], evidence_refs: ["E0", "E1"], source: binding("cvss", "/assessments/0") } };
  row.dossier = buildFindingDossier({ candidate, decision, roles, runtimeEvidence, integrated, source: { finding: binding("input", "/candidates/0/finding"), runtime: binding("runtime", "/packets") } });
  return { row, candidate, decision, roles };
}
