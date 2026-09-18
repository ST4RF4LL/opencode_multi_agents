import { findingObjectDigest } from "../../finding-evidence-contract/scripts/finding-contract.mjs";
import { validateFindingReportDetails } from "../../finding-evidence-contract/scripts/finding-report-details.mjs";
import { runtimeForFinding } from "../../../../lib/runtime-testing/evidence.mjs";

export const REPORT_DETAIL_CONTRACT = "audit-report-details.v1";
const copy = value => structuredClone(value);
const bound = value => value && typeof value.artifact === "string" && /^[a-f0-9]{64}$/.test(value.digest ?? "") && value.json_pointer?.startsWith("/");

export function findingDeliveryGaps(finding) {
  const missing = [];
  if (!finding.report_details) missing.push("上游候选未提供版本化的成因说明、复现设计、修复步骤和回归用例；当前仅保留已有证据，不补造缺失内容。");
  if (finding.report_details?.code_context?.state === "UNAVAILABLE") missing.push(`代码上下文未提供：${finding.report_details.code_context.reason}`);
  if (!/[\u3400-\u9fff]/u.test(finding.title ?? "")) missing.push("历史候选缺少中文漏洞标题，需由责任审计 Agent 核对翻译。");
  return missing;
}

export function findingRuntimeBindings(evidence, packets) {
  const ids = new Set(packets.flatMap(packet => packet.result?.evidence_ids ?? packet.evidence_ids ?? []));
  return (evidence.evidence_bindings ?? []).filter(binding => ids.has(binding.id));
}

export function buildFindingDossier({ candidate, decision, roles, runtimeEvidence, integrated, source }) {
  const reviews = roles.flatMap(({ role, manifest, artifact }) => {
    const index = manifest.findings.findIndex(item => item.finding_id === candidate.finding_id);
    return index < 0 ? [] : [{ role, session_id: manifest.agent_session_id, review: copy(manifest.findings[index]),
      source: { artifact, digest: manifest.artifact_digest, json_pointer: `/findings/${index}` } }];
  });
  const runtime = integrated ? runtimeForFinding(runtimeEvidence, candidate) : null;
  const quick = !integrated ? runtimeEvidence.results.find(item => item.finding_id === candidate.finding_id) : null;
  return { finding: copy(candidate.finding), adjudication: copy(decision), reviews,
    origins: { artifact: copy(candidate.artifact ?? null), source_reports: copy(candidate.source_reports ?? []) },
    runtime: integrated ? { protocol: "runtime-testing.v1", status: runtime.status, reason: runtimeEvidence.reason ?? null,
      packets: copy(runtime.packets), evidence_bindings: copy(findingRuntimeBindings(runtimeEvidence, runtime.packets)), source: source.runtime }
      : { protocol: "legacy-quick", status: quick?.status ?? "NOT_TESTED", reason: quick?.summary ?? "该候选没有运行验证记录。",
        result: copy(quick ?? null), evidence_bindings: copy((runtimeEvidence.evidence_bindings ?? []).filter(binding => quick?.evidence_refs?.includes(binding.path))), source: source.runtime },
    missing_sections: findingDeliveryGaps(candidate.finding), source: source.finding };
}

export function validateFindingDossier(row) {
  const dossier = row?.dossier;
  if (!dossier || !dossier.finding || !dossier.adjudication || !Array.isArray(dossier.reviews) || !Array.isArray(dossier.missing_sections)) return ["final-report-dossier-missing"];
  const errors = [];
  const finding = dossier.finding, decision = dossier.adjudication;
  if (JSON.stringify(dossier.missing_sections) !== JSON.stringify(findingDeliveryGaps(finding))) errors.push("final-report-dossier-gaps-mismatch");
  if (!dossier.origins || !Array.isArray(dossier.origins.source_reports)) errors.push("final-report-dossier-origins-missing");
  if (finding.finding_id !== row.finding_id || findingObjectDigest(finding) !== row.finding_object_digest || !bound(dossier.source)
    || decision.finding_id !== row.finding_id || decision.finding_object_digest !== row.finding_object_digest || decision.state !== row.preliminary_state) errors.push("final-report-dossier-source-mismatch");
  for (const [field, expected] of [["evidence_facts", finding.evidence?.facts], ["primary_location", finding.locations?.primary], ["remediation", finding.remediation], ["attack_surface", finding.attack_surface]]) {
    if (JSON.stringify(row[field]) !== JSON.stringify(expected)) errors.push(`final-report-dossier-${field}-mismatch`);
  }
  errors.push(...validateFindingReportDetails(finding));
  const roles = new Set();
  for (const review of dossier.reviews) {
    if (!review || !["AFFIRMATIVE", "NEGATIVE", "MODERATOR"].includes(review.role) || roles.has(review.role)
      || review.review?.finding_id !== row.finding_id || !bound(review.source)) errors.push("final-report-dossier-review-invalid");
    roles.add(review?.role);
  }
  if (row.validation && row.validation.route !== "QUICK_DYNAMIC" && roles.size !== 3) errors.push("final-report-dossier-review-missing");
  const moderator = dossier.reviews.find(item => item.role === "MODERATOR");
  if (row.validation && row.validation.final_verdict !== row.state) errors.push("final-report-dossier-routing-state-mismatch");
  if (row.validation && row.validation.route !== "QUICK_DYNAMIC" && moderator?.review.verdict !== row.validation.final_verdict) errors.push("final-report-dossier-verdict-mismatch");
  if (!dossier.runtime || !bound(dossier.runtime.source) || !["runtime-testing.v1", "legacy-quick"].includes(dossier.runtime.protocol)) errors.push("final-report-dossier-runtime-invalid");
  if (dossier.runtime?.protocol === "runtime-testing.v1" && !Array.isArray(dossier.runtime.packets)) errors.push("final-report-dossier-runtime-packets-missing");
  if (!Array.isArray(dossier.runtime?.evidence_bindings) || dossier.runtime.evidence_bindings.some(binding => !binding?.path || !/^[a-f0-9]{64}$/.test(binding.sha256 ?? ""))) errors.push("final-report-dossier-runtime-bindings-invalid");
  return errors;
}
