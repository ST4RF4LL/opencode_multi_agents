import { createHash } from "node:crypto";
import { validateAttackSurface } from "../../finding-evidence-contract/scripts/finding-contract.mjs";
import { validateAttackSurfaceReview } from "../../finding-adjudication/scripts/finding-adjudication-contract.mjs";

const ADMITTED_FINDING_STATES = new Set(["SUPPORTED_STATIC", "SUPPORTED_RUNTIME"]);
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
  if (!isObject(model.inputs) || !["coverage_summary", "adjudication_input", "adjudication", "cvss_assessment", "attack_chains"]
    .every(key => nonEmptyString(model.inputs?.[key]))) {
    errors.push("final-report-model-inputs-invalid");
  }
  if (!isObject(model.coverage) || !validDigest(model.coverage.summary_digest)
    || !nonEmptyString(model.coverage.coverage_status) || !nonEmptyString(model.coverage.seal_state) || !Array.isArray(model.coverage.metrics)) {
    errors.push("final-report-model-coverage-invalid");
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
    const attackSurfaceReviewErrors = validateAttackSurfaceReview(finding?.attack_surface_review, finding?.state);
    if (!isObject(finding) || !nonEmptyString(finding.finding_id) || findingIds.has(finding.finding_id)
      || !ADMITTED_FINDING_STATES.has(finding.state) || !validDigest(finding.finding_object_digest) || !sourceValid(finding.source)
      || attackSurfaceErrors.length > 0 || !sourceValid(finding.attack_surface_source)
      || attackSurfaceReviewErrors.length > 0 || !sourceValid(finding.attack_surface_review_source)
      || !isObject(finding.cvss) || !nonEmptyString(finding.cvss.vector) || !Number.isFinite(finding.cvss.base_score)
      || !nonEmptyString(finding.cvss.severity) || !sourceValid(finding.cvss.source)) {
      errors.push("final-report-model-finding-invalid");
    } else findingIds.add(finding.finding_id);
  }
  for (const finding of model.excluded_findings ?? []) {
    const attackSurfaceErrors = validateAttackSurface(finding?.attack_surface);
    const attackSurfaceReviewErrors = validateAttackSurfaceReview(finding?.attack_surface_review, finding?.state);
    if (!isObject(finding) || !nonEmptyString(finding.finding_id) || findingIds.has(finding.finding_id)
      || ADMITTED_FINDING_STATES.has(finding.state) || !sourceValid(finding.source)
      || attackSurfaceErrors.length > 0 || !sourceValid(finding.attack_surface_source)
      || attackSurfaceReviewErrors.length > 0 || !sourceValid(finding.attack_surface_review_source)) {
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
    ? ["- Preconditions: none recorded."]
    : surface.preconditions.map(item => `- Precondition \`${markdownText(item.precondition_id)}\` (${item.feasibility}; facts ${factIndexes(item.evidence_fact_indexes)}): ${markdownText(item.description)}`);
  const controls = surface.controls.length === 0
    ? ["- Controls: none identified."]
    : surface.controls.map(item => `- Control \`${markdownText(item.control_id)}\` (${item.state}; facts ${factIndexes(item.evidence_fact_indexes)}): ${markdownText(item.description)}`);
  const counterevidence = surface.counterevidence.length === 0
    ? ["- Counterevidence: none identified."]
    : surface.counterevidence.map(item => `- Counterevidence (${item.disposition}; facts ${factIndexes(item.evidence_fact_indexes)}): ${markdownText(item.claim)}`);
  const blindspots = surface.blindspots.length === 0
    ? ["- Blind spots: none recorded."]
    : surface.blindspots.map(item => `- Blind spot: ${markdownText(item)}`);
  const reviewLimitations = finding.attack_surface_review.limitations.length === 0
    ? ["- Adjudication limitations: none."]
    : finding.attack_surface_review.limitations.map(item => `- Adjudication limitation: ${markdownText(item)}`);
  return [
    `### ${markdownText(finding.finding_id)}`,
    "",
    "| Fact | Assessment | Evidence facts |",
    "|---|---|---|",
    `| In scope | ${surface.in_scope.state}: ${markdownText(surface.in_scope.rationale)} | ${factIndexes(surface.in_scope.evidence_fact_indexes)} |`,
    `| Exposure | ${surface.exposure.state} — ${markdownText(surface.exposure.surface)}: ${markdownText(surface.exposure.rationale)} | ${factIndexes(surface.exposure.evidence_fact_indexes)} |`,
    `| Vector | ${surface.vector.state}: ${markdownText(surface.vector.rationale)} | ${factIndexes(surface.vector.evidence_fact_indexes)} |`,
    `| Authentication scope | ${surface.auth_scope.state}: ${markdownText(surface.auth_scope.rationale)} | ${factIndexes(surface.auth_scope.evidence_fact_indexes)} |`,
    `| Identities | attacker=${markdownText(surface.identities.attacker)}; victim=${markdownText(surface.identities.victim)}; principal=${markdownText(surface.identities.effective_principal)} | ${factIndexes(surface.identities.evidence_fact_indexes)} |`,
    `| Boundary | ${surface.boundary_crossing.state}; ${markdownText(surface.boundary_crossing.from)} → ${markdownText(surface.boundary_crossing.to)}: ${markdownText(surface.boundary_crossing.rationale)} | ${factIndexes(surface.boundary_crossing.evidence_fact_indexes)} |`,
    `| Impact | ${surface.impact.types.join(", ")}: ${markdownText(surface.impact.outcome)} | ${factIndexes(surface.impact.evidence_fact_indexes)} |`,
    `| Target reach | ${surface.target_reach.state}: ${markdownText(surface.target_reach.rationale)} | ${factIndexes(surface.target_reach.evidence_fact_indexes)} |`,
    "",
    ...preconditions,
    ...controls,
    ...counterevidence,
    ...blindspots,
    `- Confidence: ${surface.confidence.level} — ${markdownText(surface.confidence.rationale)}`,
    `- Independent attack-surface review: ${finding.attack_surface_review.disposition} — ${markdownText(finding.attack_surface_review.rationale)}`,
    ...reviewLimitations,
    `- Source binding: \`${finding.attack_surface_source.digest}\`${markdownText(finding.attack_surface_source.json_pointer)}.`,
    `- Review binding: \`${finding.attack_surface_review_source.digest}\`${markdownText(finding.attack_surface_review_source.json_pointer)}.`,
    "",
  ];
}

export function renderFinalReport(model) {
  const metricRows = (model.coverage.metrics ?? []).map(metric => {
    const [fraction, percentage, state] = displayMetric(metric);
    return `| ${metric.metric_id} | ${fraction} | ${percentage} | ${state} |`;
  });
  const findingRows = model.findings.length === 0
    ? ["| _None_ | N/A | N/A |"]
    : model.findings.map(finding => `| ${finding.finding_id} | ${finding.state} | ${finding.cvss.base_score} (${finding.cvss.severity}) | ${finding.finding_object_digest} |`);
  const chainRows = model.chains.length === 0
    ? ["| _None_ | N/A | N/A |"]
    : model.chains.map(chain => `| ${chain.chain_id} | ${chain.assessment_state} | ${chain.first_blocking_step_id ?? "N/A"} |`);
  const excludedFindingRows = model.excluded_findings.length === 0
    ? ["| _None_ | N/A |"]
    : model.excluded_findings.map(finding => `| ${finding.finding_id} | ${finding.state} |`);
  const rejectedChainRows = model.rejected_chains.length === 0
    ? ["| _None_ | N/A |"]
    : model.rejected_chains.map(chain => `| ${chain.chain_id} | ${chain.assessment_state} |`);
  const attackSurfaceSections = model.findings.length === 0
    ? ["_No supported findings._", ""]
    : model.findings.flatMap(renderAttackSurfaceFinding);
  return [
    `<!-- GENERATED: final-report-model ${model.manifest_digest} -->`,
    model.report_kind === "FINAL" ? "# Security Audit Report"
      : model.report_kind === "POLICY_FINAL" ? "# Security Audit Report (Policy Accepted)"
        : model.report_kind === "PARTIAL_FINAL" ? "# Security Audit Report (Partial)" : "# Security Audit Checkpoint",
    "",
    "## Report State",
    "",
    `Audit: \`${model.audit_id}\`. Coverage status: **${model.coverage.coverage_status}**. Policy: **${model.coverage.policy_mode ?? "assurance"}** (${model.coverage.policy_satisfied ? "SATISFIED" : "NOT SATISFIED"}).`,
    ...(model.report_kind === "CHECKPOINT"
      ? ["", "This is a nonterminal checkpoint. Unverified checks remain gaps; it is not eligible for final-report review or a complete-audit claim."]
      : model.report_kind === "PARTIAL_FINAL"
        ? ["", "This is a terminal partial report. Unverified checks remain explicit gaps; it must not be presented as a complete-audit claim."]
        : model.report_kind === "POLICY_FINAL" && model.coverage.coverage_status !== "COMPLETE"
          ? ["", "This report satisfies the configured workflow policy, while unverified checks remain explicit coverage gaps. It must not be presented as a complete-coverage claim."]
      : []),
    "",
    "## Machine-Derived Coverage",
    "",
    "| Metric | Verified/Required | Percentage | State |",
    "|---|---:|---:|---|",
    ...metricRows,
    "",
    "## Adjudicated Findings",
    "",
    "| ID | Assessment | CVSS 3.1 Base | Finding Object Digest |",
    "|---|---|---:|---|",
    ...findingRows,
    "",
    "## Per-Finding Attack Surface",
    "",
    ...attackSurfaceSections,
    "## Attack Chains",
    "",
    "| ID | Assessment | First Blocking Step |",
    "|---|---|---|",
    ...chainRows,
    "",
    "## Residual Outcomes",
    "",
    "### Excluded Finding Candidates",
    "",
    "| ID | Outcome |",
    "|---|---|",
    ...excludedFindingRows,
    "",
    "### Contradicted Chains",
    "",
    "| ID | Outcome |",
    "|---|---|",
    ...rejectedChainRows,
    "",
    "This report is deterministically rendered from the model above. `CONDITIONAL` chains are unresolved hypotheses, not supported exploit paths.",
    "",
  ].join("\n");
}
