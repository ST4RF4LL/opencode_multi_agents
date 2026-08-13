#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  stageDeliveryManifestDigest,
  stageDeliveryRegistryDigest,
  validateStageDeliveryManifest,
  validateStageDeliveryRegistry,
} from "../skills/common-subagent/audit-artifact-management/scripts/stage-delivery-contract.mjs";
import { inspectStageDeliveryManifest, validateQuickEvidenceMaterialization, verifyAuditStageDeliveries } from "../skills/common-subagent/audit-artifact-management/scripts/stage-delivery-materialization.mjs";
import { artifactSetDigest, validateArtifactSetIndex } from "../skills/common-subagent/audit-artifact-management/scripts/artifact-set-contract.mjs";
import { candidateManifestDigest } from "../skills/common-subagent/finding-adjudication/scripts/finding-adjudication-contract.mjs";
import { cvssAssessmentManifestDigest } from "../skills/common-subagent/finding-adjudication/scripts/cvss-assessment-contract.mjs";
import { attackChainManifestDigest } from "../skills/attack-chain-subagent/system-attack-chain-hunting/scripts/attack-chain-contract.mjs";
import { truthValidationArtifactDigest } from "../skills/vulnerability-validator-subagent/vulnerability-validation/scripts/truth-validation-contract.mjs";
import { finalReportModelDigest, renderFinalReport } from "../skills/common-subagent/audit-coverage-accounting/scripts/final-report-model-core.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const OPENCODE = resolve(HERE, "..");
const CONTRACTS = join(OPENCODE, "skills/common-subagent/audit-artifact-management/contracts");

const [registry, stageAgentRegistry, scopeExample] = await Promise.all([
  readFile(join(CONTRACTS, "workbench-stage-deliveries.json"), "utf8").then(JSON.parse),
  readFile(join(CONTRACTS, "stage-agent-contracts.json"), "utf8").then(JSON.parse),
  readFile(join(CONTRACTS, "examples/stage-delivery.scope.example.json"), "utf8").then(JSON.parse),
]);
const DIGEST = "a".repeat(64);

function renderPath(template, auditId, round) {
  return template
    .replaceAll("{audit_id}", auditId)
    .replaceAll("{round}", String(round))
    .replaceAll(/\{[a-z0-9_]+\}/gi, "fixture")
    .replaceAll("*", "fixture");
}

function binding(template, auditId, round) {
  return {
    artifact_type: template.artifact_type,
    path: renderPath(template.path_template, auditId, round),
    sha256: DIGEST,
    media_type: template.path_template.endsWith(".md") ? "text/markdown" : "application/json",
    json_pointer: null,
  };
}

function completeManifest(stage, { activatedConditions = [], round = 1 } = {}) {
  const auditId = `audit-${stage.stage_id}-template`;
  const active = new Set(activatedConditions);
  const feedbackEdges = registry.feedback_edges.filter(edge => edge.to_stage_id === stage.stage_id && active.has(edge.condition_id));
  const predecessorManifests = stage.predecessor_stage_ids.map(stageId => ({
    stage_id: stageId,
    round,
    path: `reports/stage-deliveries/${auditId}/${stageId}.r${round}.json`,
    sha256: DIGEST,
    manifest_digest: DIGEST,
    status: "COMPLETE",
  }));
  for (const edge of feedbackEdges) predecessorManifests.push({
    stage_id: edge.from_stage_id,
    round: round - 1,
    path: `reports/stage-deliveries/${auditId}/${edge.from_stage_id}.r${round - 1}.json`,
    sha256: DIGEST,
    manifest_digest: DIGEST,
    status: edge.allowed_source_statuses[0],
  });
  const included = template => template.requirement === "REQUIRED"
    || (template.requirement === "CONDITIONAL" && active.has(template.condition_id));
  const manifest = {
    schema_version: 1,
    registry_id: registry.registry_id,
    registry_digest: registry.registry_digest,
    template_id: stage.template_id,
    stage_id: stage.stage_id,
    stage_order: stage.order,
    audit_id: auditId,
    round,
    status: "COMPLETE",
    scope_binding: { state: "FROZEN", scope_digest: DIGEST },
    activated_conditions: activatedConditions,
    predecessor_manifests: predecessorManifests,
    input_artifacts: stage.input_artifacts.filter(included).map(template => binding(template, auditId, round)),
    output_artifacts: stage.output_artifacts.filter(included).map(template => binding(template, auditId, round)),
    validation_results: stage.validators.filter(included).map(validator => ({
      validator_id: validator.validator_id,
      status: "PASS",
      checked_artifact_types: validator.artifact_types,
      evidence_refs: [],
      issues: [],
    })),
    gaps: [],
    producer: {
      agent_name: "security-audit-orchestrator",
      agent_session_id: `orchestrator-${stage.stage_id}-r${round}`,
      internal_stage_ids: stage.internal_stage_ids,
      stage_agent_contract_ids: stage.stage_agent_contract_ids,
    },
    started_at: "2026-08-12T00:00:00.000Z",
    completed_at: "2026-08-12T01:00:00.000Z",
    completion: {
      required_outputs_satisfied: true,
      required_validators_passed: true,
      predecessors_complete: true,
      complete: true,
    },
  };
  manifest.manifest_digest = stageDeliveryManifestDigest(manifest);
  return manifest;
}

assert.deepEqual(validateStageDeliveryRegistry(registry, stageAgentRegistry), []);
assert.equal(registry.registry_digest, stageDeliveryRegistryDigest(registry));
assert.equal(registry.lifecycle.state, "ACTIVE");
assert.equal(registry.lifecycle.enforcement, "ENFORCED");
assert.deepEqual(registry.stages.map(stage => stage.stage_id), [
  "scope", "recon", "threat", "audit", "correlation", "adjudication", "validation", "report",
]);
assert(registry.feedback_edges.some(edge => edge.from_stage_id === "correlation" && edge.to_stage_id === "audit"));
assert.deepEqual(validateStageDeliveryManifest(scopeExample, registry, { stageAgentRegistry }), []);
assert.equal(scopeExample.manifest_digest, stageDeliveryManifestDigest(scopeExample));
for (const stage of registry.stages) {
  const manifest = completeManifest(stage);
  assert.deepEqual(validateStageDeliveryManifest(manifest, registry, { stageAgentRegistry }), [], `complete ${stage.stage_id} template is invalid`);
}

const auditFeedback = completeManifest(registry.stages.find(stage => stage.stage_id === "audit"), {
  activatedConditions: ["correlation_gap_round"],
  round: 2,
});
assert.equal(auditFeedback.predecessor_manifests.find(item => item.stage_id === "correlation").status, "PARTIAL");
assert.deepEqual(validateStageDeliveryManifest(auditFeedback, registry, { stageAgentRegistry }), []);

const incomplete = structuredClone(scopeExample);
incomplete.output_artifacts = incomplete.output_artifacts.filter(item => item.artifact_type !== "scope-manifest");
incomplete.manifest_digest = stageDeliveryManifestDigest(incomplete);
const incompleteErrors = validateStageDeliveryManifest(incomplete, registry, { stageAgentRegistry });
assert(incompleteErrors.includes("stage-delivery-output-required-artifact-missing:scope-manifest"));
assert(incompleteErrors.includes("stage-delivery-complete-gate-not-satisfied"));

const failedValidation = structuredClone(scopeExample);
failedValidation.validation_results[0].status = "FAIL";
failedValidation.validation_results[0].issues = ["P01 output digest mismatch"];
failedValidation.manifest_digest = stageDeliveryManifestDigest(failedValidation);
assert(validateStageDeliveryManifest(failedValidation, registry, { stageAgentRegistry }).includes("stage-delivery-complete-gate-not-satisfied"));

const partial = structuredClone(scopeExample);
partial.status = "PARTIAL";
partial.validation_results[0].status = "FAIL";
partial.validation_results[0].issues = ["P01 output digest mismatch"];
partial.gaps = [{
  gap_id: "GAP-SCOPE-001",
  category: "handoff-digest",
  description: "P01 输出摘要与范围输入不一致。",
  blocking: true,
  evidence_refs: ["reports/handoffs/audit-template-example/P01_RECON/security-intel-collector.intel-recon-r1.output.json"],
}];
partial.completed_at = null;
partial.completion.required_validators_passed = false;
partial.completion.complete = false;
partial.manifest_digest = stageDeliveryManifestDigest(partial);
assert.deepEqual(validateStageDeliveryManifest(partial, registry, { stageAgentRegistry }), []);

const unknownContract = structuredClone(registry);
unknownContract.stages[0].stage_agent_contract_ids.push("P99_UNKNOWN.agent");
unknownContract.registry_digest = stageDeliveryRegistryDigest(unknownContract);
assert(validateStageDeliveryRegistry(unknownContract, stageAgentRegistry).includes("stage:scope:stage-agent-contract-id-unknown:P99_UNKNOWN.agent"));

const brokenLink = structuredClone(registry);
brokenLink.stages[3].input_artifacts.find(item => item.artifact_type === "recon-inventory-set").artifact_type = "missing-upstream-type";
brokenLink.registry_digest = stageDeliveryRegistryDigest(brokenLink);
assert(validateStageDeliveryRegistry(brokenLink, stageAgentRegistry)
  .includes("stage:audit:input-not-produced:missing-upstream-type:recon"));

const report = registry.stages.find(stage => stage.stage_id === "report");
assert.deepEqual(report.completion_gate.required_output_types, ["final-report-model", "final-report"]);
assert(!report.output_artifacts.some(artifact => artifact.artifact_type.startsWith("third-party-review")));
const adjudication = registry.stages.find(stage => stage.stage_id === "adjudication");
assert(!adjudication.output_artifacts.some(artifact => ["cvss-assessment", "attack-chain-report"].includes(artifact.artifact_type)));
const validation = registry.stages.find(stage => stage.stage_id === "validation");
assert(validation.output_artifacts.some(artifact => artifact.artifact_type === "validation-routing-manifest"));
assert(validation.output_artifacts.some(artifact => artifact.artifact_type === "cvss-assessment"));
assert(validation.validators.some(validator => validator.validator_id === "truth-validation-contract"));

const emptySet = {
  schema_version: 1,
  set_type: "finding-artifact-set",
  audit_id: "audit-artifact-set-template",
  round: 1,
  scope_digest: DIGEST,
  items: [],
  item_count: 0,
};
emptySet.set_digest = artifactSetDigest(emptySet);
assert.deepEqual(validateArtifactSetIndex(emptySet, { expectedSetType: "finding-artifact-set" }), []);
const badSetCount = structuredClone(emptySet);
badSetCount.item_count = 1;
badSetCount.set_digest = artifactSetDigest(badSetCount);
assert(validateArtifactSetIndex(badSetCount).includes("artifact-set-item-count-invalid"));

function bytesDigest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function writeArtifact(reportsRoot, path, contents = null) {
  const relative = path.slice("reports/".length);
  const absolute = join(reportsRoot, relative);
  await mkdir(dirname(absolute), { recursive: true });
  const bytes = Buffer.from(contents ?? `${JSON.stringify({ path })}\n`);
  await writeFile(absolute, bytes);
  return bytesDigest(bytes);
}

async function quickEvidenceFixture() {
  const root = await mkdtemp(join(tmpdir(), "stage-delivery-quick-evidence-"));
  const reportsRoot = join(root, "reports");
  const evidencePath = "reports/validation/quick/evidence/audit-quick-evidence/observation.json";
  try {
    const sha256 = await writeArtifact(reportsRoot, evidencePath, "{}\n");
    const file = {
      ok: true,
      bytes: Buffer.from(JSON.stringify({ evidence_bindings: [{ path: evidencePath, sha256, media_type: "application/json" }] })),
    };
    const errors = [];
    await validateQuickEvidenceMaterialization({ reportsRoot, file, errors });
    assert.deepEqual(errors, []);
    await writeArtifact(reportsRoot, evidencePath, "tampered\n");
    const tamperedErrors = [];
    await validateQuickEvidenceMaterialization({ reportsRoot, file, errors: tamperedErrors });
    assert(tamperedErrors.some(error => error.includes("artifact-sha256-mismatch")));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function sealerFixture() {
  const root = await mkdtemp(join(tmpdir(), "stage-delivery-sealer-"));
  const reportsRoot = join(root, "reports");
  const auditId = "audit-sealer-fixture";
  const stage = registry.stages.find(item => item.stage_id === "scope");
  try {
    await mkdir(join(root, "tmp"), { recursive: true });
    const inputArtifacts = [];
    for (const template of stage.input_artifacts.filter(item => item.requirement === "REQUIRED")) {
      const path = renderPath(template.path_template, auditId, 1);
      await writeArtifact(reportsRoot, path);
      inputArtifacts.push({ artifact_type: template.artifact_type, path, json_pointer: null });
    }
    const outputArtifacts = [];
    for (const template of stage.output_artifacts.filter(item => item.requirement === "REQUIRED")) {
      const path = renderPath(template.path_template, auditId, 1);
      await writeArtifact(reportsRoot, path);
      outputArtifacts.push({ artifact_type: template.artifact_type, path, json_pointer: null });
    }
    const request = {
      stage_id: stage.stage_id,
      audit_id: auditId,
      round: 1,
      status: "COMPLETE",
      scope_digest: DIGEST,
      activated_conditions: [],
      input_artifacts: inputArtifacts,
      output_artifacts: outputArtifacts,
      validation_results: stage.validators.map(validator => ({
        validator_id: validator.validator_id,
        status: "PASS",
        checked_artifact_types: validator.artifact_types,
        evidence_refs: [outputArtifacts[0].path],
        issues: [],
      })),
      gaps: [],
      producer: {
        agent_name: "security-audit-orchestrator",
        agent_session_id: "orchestrator-sealer-r1",
        internal_stage_ids: stage.internal_stage_ids,
        stage_agent_contract_ids: stage.stage_agent_contract_ids,
      },
      started_at: "2026-08-12T00:00:00.000Z",
      completed_at: "2026-08-12T01:00:00.000Z",
    };
    const requestPath = join(root, "tmp/stage-request.json");
    await writeFile(requestPath, `${JSON.stringify(request, null, 2)}\n`);
    const run = () => spawnSync(process.execPath, [
      join(OPENCODE, "skills/common-subagent/audit-artifact-management/scripts/seal-stage-delivery.mjs"),
      "--request", "tmp/stage-request.json",
    ], {
      cwd: root,
      env: { ...process.env, AUDIT_WORKSPACE_ROOT: root, AUDIT_REPORTS_ROOT: reportsRoot },
      encoding: "utf8",
    });
    const first = run();
    assert.equal(first.status, 0, first.stderr);
    const second = run();
    assert.equal(second.status, 0, second.stderr);
    const manifestPath = `reports/stage-deliveries/${auditId}/scope.r1.json`;
    const inspected = await inspectStageDeliveryManifest({ reportsRoot, manifestPath, registry, stageAgentRegistry });
    assert.equal(inspected.complete, true, inspected.errors.join("\n"));
    await writeArtifact(reportsRoot, outputArtifacts[0].path, "tampered\n");
    const tampered = await inspectStageDeliveryManifest({ reportsRoot, manifestPath, registry, stageAgentRegistry });
    assert.equal(tampered.complete, false);
    assert(tampered.errors.some(error => error.includes("artifact-sha256-mismatch")));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function materializedFixture() {
  const root = await mkdtemp(join(tmpdir(), "stage-delivery-materialized-"));
  const reportsRoot = join(root, "reports");
  const auditId = "audit-materialized-fixture";
  const manifests = new Map();
  const candidateInput = {
    schema_version: 1,
    audit_id: auditId,
    scope_digest: DIGEST,
    plan_digest: "b".repeat(64),
    structural_digest: "c".repeat(64),
    candidates: [],
  };
  candidateInput.manifest_digest = candidateManifestDigest(candidateInput);
  const adjudicationResult = {
    schema_version: 1,
    audit_id: auditId,
    scope_digest: DIGEST,
    input_manifest_digest: candidateInput.manifest_digest,
    adjudicator_session_id: "adjudicator-materialized-r1",
    decisions: [],
  };
  adjudicationResult.manifest_digest = candidateManifestDigest(adjudicationResult);
  const sealTruth = value => {
    value.artifact_digest = truthValidationArtifactDigest(value);
    return value;
  };
  const truthIntake = sealTruth({
    schema_version: 1,
    artifact_type: "finding-truth-validation-intake",
    audit_id: auditId,
    round: 1,
    scope_digest: DIGEST,
    policy: {
      quick_dynamic: { enabled: false, explicit_task_opt_in: false, deadline_seconds: 120, target_scope: "LOOPBACK_ONLY" },
      static_review: "AFFIRMATIVE_NEGATIVE_MODERATOR",
      full_dynamic_trigger: "MANUAL_ONLY",
    },
    findings: [],
  });
  const quickResult = sealTruth({
    schema_version: 1,
    artifact_type: "quick-dynamic-result-set",
    audit_id: auditId,
    round: 1,
    intake_digest: truthIntake.artifact_digest,
    deadline_seconds: 120,
    elapsed_ms: 0,
    deadline_exceeded: false,
    evidence_bindings: [],
    results: [],
  });
  const staticReview = (role, bindings = {}) => sealTruth({
    schema_version: 1,
    artifact_type: "static-truth-review",
    audit_id: auditId,
    round: 1,
    role,
    execution_status: "NOT_APPLICABLE",
    agent_session_id: null,
    intake_digest: truthIntake.artifact_digest,
    quick_result_digest: quickResult.artifact_digest,
    ...bindings,
    reviewed_finding_ids: [],
    findings: [],
  });
  const affirmativeReview = staticReview("AFFIRMATIVE");
  const negativeReview = staticReview("NEGATIVE", { affirmative_review_digest: affirmativeReview.artifact_digest });
  const moderatorReview = staticReview("MODERATOR", {
    affirmative_review_digest: affirmativeReview.artifact_digest,
    negative_review_digest: negativeReview.artifact_digest,
  });
  const routing = sealTruth({
    schema_version: 1,
    artifact_type: "finding-validation-routing-manifest",
    audit_id: auditId,
    round: 1,
    scope_digest: DIGEST,
    intake_digest: truthIntake.artifact_digest,
    quick_result_digest: quickResult.artifact_digest,
    role_review_digests: {
      affirmative: affirmativeReview.artifact_digest,
      negative: negativeReview.artifact_digest,
      moderator: moderatorReview.artifact_digest,
    },
    full_dynamic_trigger: "MANUAL_ONLY",
    findings: [],
    summary: { total: 0, true_positive: 0, false_positive: 0, inconclusive: 0 },
    complete: true,
  });
  const cvss = {
    schema_version: 1,
    audit_id: auditId,
    scope_digest: DIGEST,
    adjudication_manifest_digest: adjudicationResult.manifest_digest,
    validation_routing_digest: routing.artifact_digest,
    assessments: [],
  };
  cvss.manifest_digest = cvssAssessmentManifestDigest(cvss);
  const chains = {
    schema_version: 2,
    audit_id: auditId,
    scope_digest: DIGEST,
    adjudication_manifest_digest: adjudicationResult.manifest_digest,
    validation_routing_digest: routing.artifact_digest,
    chains: [],
    gaps: [],
    chain_accounting: { raw_chain_ids: [], accepted_chain_ids: [], rejected_chain_ids: [] },
  };
  chains.manifest_digest = attackChainManifestDigest(chains);
  const finalModel = {
    schema_version: 1,
    audit_id: auditId,
    scope_digest: DIGEST,
    report_kind: "FINAL",
    coverage: {
      summary_digest: "d".repeat(64),
      coverage_status: "COMPLETE",
      seal_state: "FINALIZED_COMPLETE",
      policy_mode: "assurance",
      policy_satisfied: true,
      metrics: [],
    },
    truth_validation: {
      routing_digest: routing.artifact_digest,
      full_dynamic_trigger: "MANUAL_ONLY",
      summary: routing.summary,
      source: {
        artifact: `reports/validation/validation-routing.${auditId}.r1.json`,
        digest: routing.artifact_digest,
        json_pointer: "/summary",
      },
    },
    inputs: {
      coverage_summary: "reports/coverage/coverage-summary.json",
      adjudication_input: "reports/adjudication/finding-input.json",
      adjudication: "reports/adjudication/finding-adjudication.json",
      truth_validation_intake: "reports/validation/intake.json",
      quick_dynamic_results: "reports/validation/quick.json",
      affirmative_review: "reports/validation/affirmative.json",
      negative_review: "reports/validation/negative.json",
      moderator_review: "reports/validation/moderator.json",
      validation_routing: "reports/validation/routing.json",
      cvss_assessment: "reports/adjudication/cvss.json",
      attack_chains: "reports/attack-chains/chains.json",
    },
    findings: [],
    excluded_findings: [],
    chains: [],
    rejected_chains: [],
  };
  finalModel.manifest_digest = finalReportModelDigest(finalModel);
  const knownContents = new Map([
    ["finding-adjudication-input", `${JSON.stringify(candidateInput, null, 2)}\n`],
    ["finding-adjudication", `${JSON.stringify(adjudicationResult, null, 2)}\n`],
    ["truth-validation-intake", `${JSON.stringify(truthIntake, null, 2)}\n`],
    ["quick-dynamic-result-set", `${JSON.stringify(quickResult, null, 2)}\n`],
    ["affirmative-review", `${JSON.stringify(affirmativeReview, null, 2)}\n`],
    ["negative-review", `${JSON.stringify(negativeReview, null, 2)}\n`],
    ["moderator-review", `${JSON.stringify(moderatorReview, null, 2)}\n`],
    ["validation-routing-manifest", `${JSON.stringify(routing, null, 2)}\n`],
    ["cvss-assessment", `${JSON.stringify(cvss, null, 2)}\n`],
    ["attack-chain-report", `${JSON.stringify(chains, null, 2)}\n`],
    ["final-report-model", `${JSON.stringify(finalModel, null, 2)}\n`],
    ["final-report", renderFinalReport(finalModel)],
  ]);
  await mkdir(reportsRoot, { recursive: true });
  for (const stage of registry.stages) {
    const bind = async template => {
      const path = renderPath(template.path_template, auditId, 1);
      let contents = knownContents.get(template.artifact_type) ?? null;
      if (template.contract_ref?.endsWith("artifact-set-index-v1.schema.json")) {
        const items = [];
        if (template.artifact_type === "finding-artifact-set") {
          const memberPath = `reports/findings/${auditId}/empty-fixture.json`;
          const memberSha = await writeArtifact(reportsRoot, memberPath, "{}\n");
          items.push({ artifact_type: "finding-artifact", path: memberPath, sha256: memberSha, media_type: "application/json", json_pointer: null });
        }
        const setIndex = {
          schema_version: 1,
          set_type: template.artifact_type,
          audit_id: auditId,
          round: 1,
          scope_digest: DIGEST,
          items,
          item_count: items.length,
        };
        setIndex.set_digest = artifactSetDigest(setIndex);
        contents = `${JSON.stringify(setIndex, null, 2)}\n`;
      }
      const sha256 = await writeArtifact(reportsRoot, path, contents);
      return { artifact_type: template.artifact_type, path, sha256, media_type: path.endsWith(".md") ? "text/markdown" : "application/json", json_pointer: null };
    };
    const included = item => item.requirement === "REQUIRED";
    const inputArtifacts = [];
    for (const template of stage.input_artifacts.filter(included)) inputArtifacts.push(await bind(template));
    const outputArtifacts = [];
    for (const template of stage.output_artifacts.filter(included)) outputArtifacts.push(await bind(template));
    const predecessors = [];
    for (const predecessorId of stage.predecessor_stage_ids) {
      const prior = manifests.get(predecessorId);
      predecessors.push({
        stage_id: predecessorId,
        round: 1,
        path: prior.path,
        sha256: prior.sha256,
        manifest_digest: prior.manifest.manifest_digest,
        status: "COMPLETE",
      });
    }
    const evidencePath = outputArtifacts[0]?.path ?? inputArtifacts[0].path;
    const manifest = {
      schema_version: 1,
      registry_id: registry.registry_id,
      registry_digest: registry.registry_digest,
      template_id: stage.template_id,
      stage_id: stage.stage_id,
      stage_order: stage.order,
      audit_id: auditId,
      round: 1,
      status: "COMPLETE",
      scope_binding: { state: "FROZEN", scope_digest: DIGEST },
      activated_conditions: [],
      predecessor_manifests: predecessors,
      input_artifacts: inputArtifacts,
      output_artifacts: outputArtifacts,
      validation_results: stage.validators.filter(included).map(validator => ({
        validator_id: validator.validator_id,
        status: "PASS",
        checked_artifact_types: validator.artifact_types,
        evidence_refs: [evidencePath],
        issues: [],
      })),
      gaps: [],
      producer: {
        agent_name: "security-audit-orchestrator",
        agent_session_id: `orchestrator-${stage.stage_id}-r1`,
        internal_stage_ids: stage.internal_stage_ids,
        stage_agent_contract_ids: stage.stage_agent_contract_ids,
      },
      started_at: "2026-08-12T00:00:00.000Z",
      completed_at: "2026-08-12T01:00:00.000Z",
      completion: { required_outputs_satisfied: true, required_validators_passed: true, predecessors_complete: true, complete: true },
    };
    manifest.manifest_digest = stageDeliveryManifestDigest(manifest);
    assert.deepEqual(validateStageDeliveryManifest(manifest, registry, { stageAgentRegistry }), []);
    const path = `reports/stage-deliveries/${auditId}/${stage.stage_id}.r1.json`;
    const sha256 = await writeArtifact(reportsRoot, path, `${JSON.stringify(manifest, null, 2)}\n`);
    manifests.set(stage.stage_id, { manifest, path, sha256 });
  }
  const complete = await verifyAuditStageDeliveries({ reportsRoot, auditId, registry, stageAgentRegistry });
  assert.equal(complete.complete, true, complete.errors.join("\n"));
  assert.equal(complete.completed_count, 8);
  const reportManifest = manifests.get("report").manifest;
  const finalReport = reportManifest.output_artifacts.find(item => item.artifact_type === "final-report");
  await writeArtifact(reportsRoot, finalReport.path, "tampered\n");
  const tampered = await verifyAuditStageDeliveries({ reportsRoot, auditId, registry, stageAgentRegistry });
  assert.equal(tampered.complete, false);
  assert(tampered.errors.some(error => error.includes("artifact-sha256-mismatch")));
  await rm(root, { recursive: true, force: true });
}

await materializedFixture();
await sealerFixture();
await quickEvidenceFixture();

process.stdout.write(`${JSON.stringify({
  complete: true,
  stage_delivery_contract: "v1",
  stages: registry.stages.length,
  feedback_edges: registry.feedback_edges.length,
  cases: 36,
})}\n`);
