export const FINDING_DETAIL_CONTRACT = "finding-details.v1";
const object = value => value && typeof value === "object" && !Array.isArray(value);
const text = value => typeof value === "string" && value.trim().length > 0;
const chinese = value => text(value) && /[\u3400-\u9fff]/u.test(value);
const strings = value => Array.isArray(value) && value.every(text);

// This is a proposed reproduction procedure. Execution evidence has its own
// controller-bound runtime contract and must never be inferred from this block.
export function validateFindingReportDetails(finding, { required = false } = {}) {
  const detail = finding?.report_details;
  if (detail === undefined) return required ? ["finding-report-details-missing"] : [];
  const errors = [];
  if (!object(detail) || detail.contract !== FINDING_DETAIL_CONTRACT) return ["finding-report-details-contract-invalid"];
  if (!chinese(finding.title)) errors.push("finding-report-title-chinese-required");
  if (!object(detail.root_cause) || !["summary", "expected_behavior", "actual_behavior"].every(key => chinese(detail.root_cause[key]))) errors.push("finding-report-root-cause-incomplete");
  const facts = finding.evidence?.facts ?? [];
  const refs = value => Array.isArray(value) && value.length > 0 && new Set(value).size === value.length && value.every(index => Number.isInteger(index) && index >= 0 && index < facts.length);
  const code = detail.code_context;
  if (!object(code) || !["RECORDED", "UNAVAILABLE"].includes(code.state) || !Array.isArray(code.snippets)
    || (code.state === "UNAVAILABLE" && (!chinese(code.reason) || code.snippets.length !== 0))
    || (code.state === "RECORDED" && (!code.snippets.length || code.snippets.some(snippet => !object(snippet)
      || !refs([snippet.evidence_fact_index]) || !text(snippet.text) || !/^[a-z0-9_-]+$/i.test(snippet.language ?? "") || typeof snippet.redacted !== "boolean")))) errors.push("finding-report-code-context-invalid");
  if (!Array.isArray(detail.path) || detail.path.length < 2 || detail.path.some(step => !object(step) || !chinese(step.description) || !refs(step.evidence_fact_indexes))) errors.push("finding-report-path-incomplete");
  const reproduction = detail.reproduction;
  if (!object(reproduction) || reproduction.execution_status !== "NOT_RUN" || !chinese(reproduction.environment_requirements)
    || !strings(reproduction.preconditions) || !chinese(reproduction.expected_secure_result) || !chinese(reproduction.expected_vulnerable_result)
    || !Array.isArray(reproduction.steps) || !reproduction.steps.length || reproduction.steps.some(step => !chinese(step))) errors.push("finding-report-reproduction-plan-invalid");
  const remediation = detail.remediation;
  if (!object(remediation) || !Array.isArray(remediation.changes) || !remediation.changes.length || remediation.changes.some(change => !object(change)
    || !text(change.location) || !chinese(change.action) || !chinese(change.rationale))
    || !strings(remediation.temporary_mitigations) || !strings(remediation.compatibility_notes)) errors.push("finding-report-remediation-incomplete");
  if (!Array.isArray(detail.regression_tests) || !detail.regression_tests.some(test => test?.kind === "SECURITY")
    || !detail.regression_tests.some(test => test?.kind === "FUNCTIONAL") || detail.regression_tests.some(test => !object(test)
      || !["SECURITY", "FUNCTIONAL"].includes(test.kind) || !chinese(test.scenario) || !chinese(test.expected_result))) errors.push("finding-report-regression-tests-incomplete");
  return errors;
}
