import { createHash } from "node:crypto";
import { validateAttackSurface } from "../../finding-evidence-contract/scripts/finding-contract.mjs";
import { validateAttackSurfaceReview } from "../../finding-adjudication/scripts/finding-adjudication-contract.mjs";

const ADMITTED_FINDING_STATES = new Set(["TRUE_POSITIVE"]);
const PRELIMINARY_SUPPORTED_STATES = new Set(["SUPPORTED_STATIC", "SUPPORTED_RUNTIME"]);
const ADMITTED_CHAIN_STATES = new Set(["CONDITIONAL", "SUPPORTED_STATIC", "SUPPORTED_RUNTIME"]);

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function validDigest(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
}

export function finalReportModelDigest(model) {
  const copy = structuredClone(model);
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(canonicalize(copy))).digest("hex");
}

function sourceValid(source) {
  return isObject(source) && nonEmptyString(source.artifact) && validDigest(source.digest)
    && nonEmptyString(source.json_pointer) && source.json_pointer.startsWith("/");
}

export function validateFinalReportModel(model) {
  const errors = [];
  if (!isObject(model)) return ["final-report-model-not-object"];
  if (model.schema_version !== 1) errors.push("final-report-model-schema-version-invalid");
  if (!nonEmptyString(model.audit_id) || !validDigest(model.scope_digest)) errors.push("final-report-model-audit-or-scope-invalid");
  if (!new Set(["FINAL", "POLICY_FINAL", "PARTIAL_FINAL", "CHECKPOINT"]).has(model.report_kind)) errors.push("final-report-model-kind-invalid");
  if (!isObject(model.inputs) || !["coverage_summary", "adjudication_input", "adjudication", "truth_validation_intake", "quick_dynamic_results", "affirmative_review", "negative_review", "moderator_review", "validation_routing", "cvss_assessment", "attack_chains"]
    .every(key => nonEmptyString(model.inputs?.[key]))) {
    errors.push("final-report-model-inputs-invalid");
  }
  if (!isObject(model.coverage) || !validDigest(model.coverage.summary_digest)
    || !nonEmptyString(model.coverage.coverage_status) || !nonEmptyString(model.coverage.seal_state) || !Array.isArray(model.coverage.metrics)) {
    errors.push("final-report-model-coverage-invalid");
  }
  if (!isObject(model.truth_validation) || !validDigest(model.truth_validation.routing_digest)
    || model.truth_validation.full_dynamic_trigger !== "MANUAL_ONLY"
    || !isObject(model.truth_validation.summary) || !sourceValid(model.truth_validation.source)) {
    errors.push("final-report-model-truth-validation-invalid");
  }
  if (model.report_kind === "FINAL" && model.coverage?.coverage_status !== "COMPLETE") errors.push("final-report-model-final-not-complete");
  if (model.report_kind === "POLICY_FINAL" && (model.coverage?.policy_satisfied !== true
    || !new Set(["FINALIZED_OBSERVED", "FINALIZED_RELEASE", "FINALIZED_COMPLETE"]).has(model.coverage?.seal_state))) {
    errors.push("final-report-model-policy-final-not-satisfied");
  }
  if (model.report_kind === "PARTIAL_FINAL" && (model.coverage?.coverage_status !== "PARTIAL" || model.coverage?.seal_state !== "FINALIZED_PARTIAL")) {
    errors.push("final-report-model-partial-final-not-terminal");
  }
  if (model.report_kind === "CHECKPOINT" && model.coverage?.coverage_status !== "PARTIAL") errors.push("final-report-model-checkpoint-not-partial");
  for (const metric of model.coverage?.metrics ?? []) {
    if (!isObject(metric) || !nonEmptyString(metric.metric_id) || !isObject(metric.value) || !sourceValid(metric.source)) {
      errors.push("final-report-model-metric-invalid");
    }
  }
  if (new Set((model.coverage?.metrics ?? []).map(metric => metric.metric_id)).size !== (model.coverage?.metrics ?? []).length) {
    errors.push("final-report-model-metric-id-duplicate");
  }
  for (const field of ["findings", "excluded_findings", "chains", "rejected_chains"]) {
    if (!Array.isArray(model[field])) errors.push(`final-report-model-${field}-missing`);
  }
  const findingIds = new Set();
  for (const finding of model.findings ?? []) {
    const attackSurfaceErrors = validateAttackSurface(finding?.attack_surface);
    const attackSurfaceReviewErrors = validateAttackSurfaceReview(finding?.attack_surface_review, finding?.preliminary_state);
    if (!isObject(finding) || !nonEmptyString(finding.finding_id) || findingIds.has(finding.finding_id)
      || !ADMITTED_FINDING_STATES.has(finding.state) || !PRELIMINARY_SUPPORTED_STATES.has(finding.preliminary_state)
      || !validDigest(finding.finding_object_digest) || !sourceValid(finding.source)
      || attackSurfaceErrors.length > 0 || !sourceValid(finding.attack_surface_source)
      || attackSurfaceReviewErrors.length > 0 || !sourceValid(finding.attack_surface_review_source)
      || !isObject(finding.validation) || finding.validation.final_verdict !== "TRUE_POSITIVE" || !sourceValid(finding.validation.source)
      || !isObject(finding.cvss) || !nonEmptyString(finding.cvss.vector) || !Number.isFinite(finding.cvss.base_score)
      || !nonEmptyString(finding.cvss.severity) || !sourceValid(finding.cvss.source)) {
      errors.push("final-report-model-finding-invalid");
    } else findingIds.add(finding.finding_id);
  }
  for (const finding of model.excluded_findings ?? []) {
    const attackSurfaceErrors = validateAttackSurface(finding?.attack_surface);
    const attackSurfaceReviewErrors = validateAttackSurfaceReview(finding?.attack_surface_review, finding?.preliminary_state);
    if (!isObject(finding) || !nonEmptyString(finding.finding_id) || findingIds.has(finding.finding_id)
      || ADMITTED_FINDING_STATES.has(finding.state) || !nonEmptyString(finding.preliminary_state)
      || !validDigest(finding.finding_object_digest) || !sourceValid(finding.source)
      || attackSurfaceErrors.length > 0 || !sourceValid(finding.attack_surface_source)
      || attackSurfaceReviewErrors.length > 0 || !sourceValid(finding.attack_surface_review_source)
      || !(finding.validation === null || (isObject(finding.validation)
        && ["FALSE_POSITIVE", "INCONCLUSIVE"].includes(finding.validation.final_verdict)
        && sourceValid(finding.validation.source)))) {
      errors.push("final-report-model-excluded-finding-invalid");
    } else findingIds.add(finding.finding_id);
  }
  const chainIds = new Set();
  for (const chain of model.chains ?? []) {
    if (!isObject(chain) || !nonEmptyString(chain.chain_id) || chainIds.has(chain.chain_id)
      || !ADMITTED_CHAIN_STATES.has(chain.assessment_state) || !sourceValid(chain.source)) {
      errors.push("final-report-model-chain-invalid");
    } else chainIds.add(chain.chain_id);
  }
  for (const chain of model.rejected_chains ?? []) {
    if (!isObject(chain) || !nonEmptyString(chain.chain_id) || chainIds.has(chain.chain_id)
      || chain.assessment_state !== "CONTRADICTED" || !sourceValid(chain.source)) {
      errors.push("final-report-model-rejected-chain-invalid");
    } else chainIds.add(chain.chain_id);
  }
  if (model.manifest_digest !== finalReportModelDigest(model)) errors.push("final-report-model-digest-invalid");
  return [...new Set(errors)];
}

function displayMetric(metric) {
  const value = metric.value;
  const fraction = value.numerator != null && value.denominator != null ? `${value.numerator}/${value.denominator}` : "N/A";
  const percentage = value.percentage == null ? value.state ?? "N/A" : `${Number(value.percentage).toFixed(2)}%`;
  return [fraction, percentage, value.state ?? "N/A"];
}

function markdownText(value) {
  return String(value ?? "N/A").replaceAll("\r", " ").replaceAll("\n", " ").replaceAll("|", "\\|");
}

function factIndexes(value) {
  return Array.isArray(value) && value.length > 0 ? value.join(", ") : "none";
}

function renderAttackSurfaceFinding(finding) {
  const surface = finding.attack_surface;
  const preconditions = surface.preconditions.length === 0
    ? ["- 前置条件：未记录。"]
    : surface.preconditions.map(item => `- 前置条件 \`${markdownText(item.precondition_id)}\`（${item.feasibility}；证据事实 ${factIndexes(item.evidence_fact_indexes)}）：${markdownText(item.description)}`);
  const controls = surface.controls.length === 0
    ? ["- 控制措施：未发现。"]
    : surface.controls.map(item => `- 控制 \`${markdownText(item.control_id)}\`（${item.state}；证据事实 ${factIndexes(item.evidence_fact_indexes)}）：${markdownText(item.description)}`);
  const counterevidence = surface.counterevidence.length === 0
    ? ["- 反证：未发现。"]
    : surface.counterevidence.map(item => `- 反证（${item.disposition}；证据事实 ${factIndexes(item.evidence_fact_indexes)}）：${markdownText(item.claim)}`);
  const blindspots = surface.blindspots.length === 0
    ? ["- 盲点：未记录。"]
    : surface.blindspots.map(item => `- 盲点：${markdownText(item)}`);
  const reviewLimitations = finding.attack_surface_review.limitations.length === 0
    ? ["- 裁决局限：无。"]
    : finding.attack_surface_review.limitations.map(item => `- 裁决局限：${markdownText(item)}`);
  return [
    `### ${markdownText(finding.finding_id)}`,
    "",
    "| 事实 | 评估 | 证据事实 |",
    "|---|---|---|",
    `| 范围 | ${surface.in_scope.state}: ${markdownText(surface.in_scope.rationale)} | ${factIndexes(surface.in_scope.evidence_fact_indexes)} |`,
    `| 暴露面 | ${surface.exposure.state} — ${markdownText(surface.exposure.surface)}: ${markdownText(surface.exposure.rationale)} | ${factIndexes(surface.exposure.evidence_fact_indexes)} |`,
    `| 向量 | ${surface.vector.state}: ${markdownText(surface.vector.rationale)} | ${factIndexes(surface.vector.evidence_fact_indexes)} |`,
    `| 认证范围 | ${surface.auth_scope.state}: ${markdownText(surface.auth_scope.rationale)} | ${factIndexes(surface.auth_scope.evidence_fact_indexes)} |`,
    `| 身份 | 攻击者=${markdownText(surface.identities.attacker)}；受害者=${markdownText(surface.identities.victim)}；有效主体=${markdownText(surface.identities.effective_principal)} | ${factIndexes(surface.identities.evidence_fact_indexes)} |`,
    `| 边界 | ${surface.boundary_crossing.state}；${markdownText(surface.boundary_crossing.from)} → ${markdownText(surface.boundary_crossing.to)}: ${markdownText(surface.boundary_crossing.rationale)} | ${factIndexes(surface.boundary_crossing.evidence_fact_indexes)} |`,
    `| 影响 | ${surface.impact.types.join(", ")}: ${markdownText(surface.impact.outcome)} | ${factIndexes(surface.impact.evidence_fact_indexes)} |`,
    `| 目标可达性 | ${surface.target_reach.state}: ${markdownText(surface.target_reach.rationale)} | ${factIndexes(surface.target_reach.evidence_fact_indexes)} |`,
    "",
    ...preconditions,
    ...controls,
    ...counterevidence,
    ...blindspots,
    `- 置信度：${surface.confidence.level} — ${markdownText(surface.confidence.rationale)}`,
    `- 独立攻击面复核：${finding.attack_surface_review.disposition} — ${markdownText(finding.attack_surface_review.rationale)}`,
    ...reviewLimitations,
    `- 来源绑定：\`${finding.attack_surface_source.digest}\`${markdownText(finding.attack_surface_source.json_pointer)}。`,
    `- 复核绑定：\`${finding.attack_surface_review_source.digest}\`${markdownText(finding.attack_surface_review_source.json_pointer)}。`,
    "",
  ];
}

export function renderFinalReport(model) {
  const metricRows = (model.coverage.metrics ?? []).map(metric => {
    const [fraction, percentage, state] = displayMetric(metric);
    return `| ${metric.metric_id} | ${fraction} | ${percentage} | ${state} |`;
  });
  const findingRows = model.findings.length === 0
    ? ["| _无_ | N/A | N/A | N/A |"]
    : model.findings.map(finding => `| ${finding.finding_id} | ${finding.state} | ${finding.cvss.base_score} (${finding.cvss.severity}) | ${finding.finding_object_digest} |`);
  const chainRows = model.chains.length === 0
    ? ["| _无_ | N/A | N/A |"]
    : model.chains.map(chain => `| ${chain.chain_id} | ${chain.assessment_state} | ${chain.first_blocking_step_id ?? "N/A"} |`);
  const excludedFindingRows = model.excluded_findings.length === 0
    ? ["| _无_ | N/A |"]
    : model.excluded_findings.map(finding => `| ${finding.finding_id} | ${finding.state} |`);
  const rejectedChainRows = model.rejected_chains.length === 0
    ? ["| _无_ | N/A |"]
    : model.rejected_chains.map(chain => `| ${chain.chain_id} | ${chain.assessment_state} |`);
  const attackSurfaceSections = model.findings.length === 0
    ? ["_没有通过真实性路由的漏洞。_", ""]
    : model.findings.flatMap(renderAttackSurfaceFinding);
  return [
    `<!-- GENERATED: final-report-model ${model.manifest_digest} -->`,
    model.report_kind === "FINAL" ? "# 安全审计报告"
      : model.report_kind === "POLICY_FINAL" ? "# 安全审计报告（策略已满足）"
        : model.report_kind === "PARTIAL_FINAL" ? "# 安全审计报告（部分完成）" : "# 安全审计检查点",
    "",
    "## 报告状态",
    "",
    `审计：\`${model.audit_id}\`。覆盖状态：**${model.coverage.coverage_status}**。策略：**${model.coverage.policy_mode ?? "assurance"}**（${model.coverage.policy_satisfied ? "已满足" : "未满足"}）。`,
    ...(model.report_kind === "CHECKPOINT"
      ? ["", "这是非终态检查点。未验证检查仍为缺口，不能作为终稿或完整审计声明。"]
      : model.report_kind === "PARTIAL_FINAL"
        ? ["", "这是终态部分报告。未验证检查仍是显式缺口，不能表述为完整审计。"]
        : model.report_kind === "POLICY_FINAL" && model.coverage.coverage_status !== "COMPLETE"
          ? ["", "本报告满足配置的流程策略，但未验证检查仍是显式覆盖缺口，不能表述为完整覆盖。"]
      : []),
    "",
    "## 机器派生覆盖情况",
    "",
    "| 指标 | 已验证/要求 | 比例 | 状态 |",
    "|---|---:|---:|---|",
    ...metricRows,
    "",
    "## 真实性验证路由",
    "",
    `快速动态与本地三方共处理 ${model.truth_validation.summary.total} 项：真实漏洞 ${model.truth_validation.summary.true_positive}，误报 ${model.truth_validation.summary.false_positive}，证据不足 ${model.truth_validation.summary.inconclusive}。完整动态验证保持人工触发。`,
    "",
    "## 已确认漏洞",
    "",
    "| ID | 终局裁定 | CVSS 3.1 基础分 | Finding 对象摘要 |",
    "|---|---|---:|---|",
    ...findingRows,
    "",
    "## 逐项攻击面证据",
    "",
    ...attackSurfaceSections,
    "## 攻击链",
    "",
    "| ID | 评估 | 首个阻断步骤 |",
    "|---|---|---|",
    ...chainRows,
    "",
    "## 排除项与剩余结果",
    "",
    "### 排除或证据不足的候选",
    "",
    "| ID | 结果 |",
    "|---|---|",
    ...excludedFindingRows,
    "",
    "### 已反驳攻击链",
    "",
    "| ID | 结果 |",
    "|---|---|",
    ...rejectedChainRows,
    "",
    "本报告由上述模型确定性渲染。`CONDITIONAL` 攻击链属于尚未解决的假设，不是已支持的利用路径。",
    "",
  ].join("\n");
}
