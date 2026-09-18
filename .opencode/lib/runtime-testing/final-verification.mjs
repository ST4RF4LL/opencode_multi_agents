import { readFile, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { verifyRuntimeEvidenceFiles, runtimeForFinding } from "./evidence.mjs";
import { check, digest } from "./contract.mjs";
import { validateTruthValidationBundle } from "../../skills/vulnerability-validator-subagent/vulnerability-validation/scripts/truth-validation-contract.mjs";
import { validateBoundFactPackets } from "../../skills/vulnerability-validator-subagent/vulnerability-validation/scripts/static-fact-packet.mjs";
import { validateFinalReportModel } from "../../skills/common-subagent/audit-coverage-accounting/scripts/final-report-model-core.mjs";
import { findingRuntimeBindings } from "../../skills/common-subagent/audit-coverage-accounting/scripts/report-dossier.mjs";

export async function verifyIntegratedFinalReport({ audit, reportsRoot }) {
  const root = await realpath(reportsRoot); const workspace = audit.paths?.workspace_root ?? process.cwd();
  async function artifact(value) {
    const path = await realpath(isAbsolute(value) ? value : resolve(workspace, value));
    const suffix = relative(root, path);
    check(suffix && suffix !== ".." && !suffix.startsWith(`..${sep}`) && !isAbsolute(suffix), "final-input-outside-reports");
    return { path, value: JSON.parse(await readFile(path, "utf8")) };
  }
  const { value: model } = await artifact(join(root, "final", `security-audit-report-model.${audit.id}.json`));
  check(model.schema_version === 3 && model.audit_id === audit.id && model.scope_digest === audit.source_baseline?.scope_digest
    && validateFinalReportModel(model).length === 0, "final-runtime-protocol-mismatch");
  const evidencePath = join(root, "runtime-testing", audit.id, "evidence-set.json");
  check(await realpath(model.inputs.runtime_testing_evidence) === await realpath(evidencePath), "final-runtime-evidence-path-mismatch");
  const fields = { intake: "truth_validation_intake", affirmative: "affirmative_review", negative: "negative_review", moderator: "moderator_review", routing: "validation_routing" };
  const bundle = {};
  for (const [key, field] of Object.entries(fields)) bundle[key] = (await artifact(model.inputs[field])).value;
  check(bundle.intake.schema_version === 3 && bundle.intake.audit_id === audit.id && bundle.intake.scope_digest === model.scope_digest, "final-runtime-intake-version-mismatch");
  bundle.quickResultSet = await verifyRuntimeEvidenceFiles(evidencePath, bundle.intake);
  await validateBoundFactPackets(workspace, bundle.intake);
  check(validateTruthValidationBundle(bundle).length === 0, "final-runtime-truth-bundle-invalid");
  const evidence = bundle.quickResultSet;
  check(evidence.authorization_digest === audit.runtime_testing_state?.authorization_digest
    && model.runtime_testing.evidence_digest === evidence.artifact_digest
    && model.runtime_testing.authorization_digest === evidence.authorization_digest
    && model.truth_validation.routing_digest === bundle.routing.artifact_digest
    && model.runtime_testing.status === evidence.status && model.runtime_testing.cleanup_status === evidence.cleanup_status
    && model.runtime_testing.reason === evidence.reason
    && digest(model.truth_validation.summary) === digest(bundle.routing.summary)
    && digest(model.runtime_testing.runtime_only_findings) === digest(bundle.routing.runtime_findings), "final-runtime-display-binding-invalid");
  const expectedPackets = evidence.packets.map(packet => ({ id: packet.id, phase: packet.phase, execution_status: packet.execution_status,
    outcome: packet.outcome, cleanup_status: packet.cleanup_status, summary: packet.summary ?? packet.reason,
    gaps: packet.result?.gaps ?? [], changes: packet.result?.changes ?? [] }));
  check(digest(model.runtime_testing.packets) === digest(expectedPackets), "final-runtime-packet-display-mismatch");
  const accepted = bundle.routing.findings.filter(row => row.final_verdict === "TRUE_POSITIVE").map(row => row.finding_id).sort();
  check(digest(model.findings.map(row => row.finding_id).sort()) === digest(accepted), "final-runtime-source-finding-accounting-invalid");
  if (model.detail_contract === "audit-report-details.v1") {
    check(digest(model.runtime_testing.details.evidence) === digest(evidence), "final-runtime-details-evidence-mismatch");
    for (const review of model.runtime_testing.details.reviews) {
      const original = bundle[review.role.toLowerCase()];
      check(review.session_id === original.agent_session_id && digest(review.findings) === digest(original.runtime_findings ?? [])
        && review.source.digest === original.artifact_digest, "final-runtime-only-review-details-mismatch");
    }
    for (const row of [...model.findings, ...model.excluded_findings]) {
      const expected = runtimeForFinding(evidence, row);
      check(row.dossier?.runtime.status === expected.status && digest(row.dossier.runtime.packets) === digest(expected.packets)
        && digest(row.dossier.runtime.evidence_bindings) === digest(findingRuntimeBindings(evidence, expected.packets)), "final-runtime-finding-details-mismatch");
      for (const { role, review } of row.dossier.reviews) {
        const original = bundle[role.toLowerCase()]?.findings.find(item => item.finding_id === row.finding_id);
        check(original && digest(review) === digest(original), "final-runtime-review-details-mismatch");
      }
    }
  }
  return true;
}
