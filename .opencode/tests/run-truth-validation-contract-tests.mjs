#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  truthValidationArtifactDigest,
  validateQuickDynamicResultSet,
  validateStaticRoleReview,
  validateTruthValidationBundle,
  validateTruthValidationIntake,
  validateValidationRoutingManifest,
} from "../skills/vulnerability-validator-subagent/vulnerability-validation/scripts/truth-validation-contract.mjs";
import { candidateManifestDigest } from "../skills/common-subagent/finding-adjudication/scripts/finding-adjudication-contract.mjs";
import { artifactSetDigest } from "../skills/common-subagent/audit-artifact-management/scripts/artifact-set-contract.mjs";

const DIGEST = "a".repeat(64);
const OPENCODE = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPTS = join(OPENCODE, "skills/vulnerability-validator-subagent/vulnerability-validation/scripts");

function runScript(name, args, { cwd, environment = {}, expected = 0 }) {
  const result = spawnSync(process.execPath, [join(SCRIPTS, name), ...args], {
    cwd,
    env: { ...process.env, ...environment },
    encoding: "utf8",
  });
  assert.equal(result.status, expected, `${name} returned ${result.status}: ${result.stderr}`);
  return result;
}

function seal(value) {
  value.artifact_digest = truthValidationArtifactDigest(value);
  return value;
}

function intake(enabled = true) {
  return seal({
    schema_version: 1,
    artifact_type: "finding-truth-validation-intake",
    audit_id: "truth-validation-fixture",
    round: 1,
    scope_digest: DIGEST,
    policy: {
      quick_dynamic: { enabled, explicit_task_opt_in: enabled, deadline_seconds: 120, target_scope: "LOOPBACK_ONLY" },
      static_review: "AFFIRMATIVE_NEGATIVE_MODERATOR",
      full_dynamic_trigger: "MANUAL_ONLY",
    },
    findings: [
      {
        finding_id: "FIND-QUICK-001",
        finding_object_digest: "b".repeat(64),
        finding_path: "reports/adjudication/finding-input.truth-validation-fixture.r1.json",
        adjudication_state: "SUPPORTED_RUNTIME",
        quick_dynamic_eligible: enabled,
        runtime_request_path: "reports/validation-handoff/runtime/truth-validation-fixture/FIND-QUICK-001.request.json",
      },
      {
        finding_id: "FIND-STATIC-002",
        finding_object_digest: "c".repeat(64),
        finding_path: "reports/adjudication/finding-input.truth-validation-fixture.r1.json",
        adjudication_state: "SUPPORTED_STATIC",
        quick_dynamic_eligible: enabled,
        runtime_request_path: null,
      },
    ],
  });
}

function quick(boundIntake) {
  return seal({
    schema_version: 1,
    artifact_type: "quick-dynamic-result-set",
    audit_id: boundIntake.audit_id,
    round: boundIntake.round,
    intake_digest: boundIntake.artifact_digest,
    deadline_seconds: 120,
    elapsed_ms: boundIntake.policy.quick_dynamic.enabled ? 2500 : 0,
    deadline_exceeded: false,
    evidence_bindings: boundIntake.policy.quick_dynamic.enabled ? [{
      path: "reports/validation/quick/evidence/truth-validation-fixture/FIND-QUICK-001.json",
      sha256: "d".repeat(64),
      media_type: "application/json",
    }] : [],
    results: boundIntake.findings.map(finding => ({
      finding_id: finding.finding_id,
      status: boundIntake.policy.quick_dynamic.enabled && finding.finding_id === "FIND-QUICK-001" ? "CONFIRMED" : "SKIPPED",
      duration_ms: boundIntake.policy.quick_dynamic.enabled && finding.finding_id === "FIND-QUICK-001" ? 2500 : 0,
      target_origin: boundIntake.policy.quick_dynamic.enabled && finding.finding_id === "FIND-QUICK-001" ? "http://127.0.0.1:4173" : null,
      evidence_refs: boundIntake.policy.quick_dynamic.enabled && finding.finding_id === "FIND-QUICK-001" ? ["reports/validation/quick/evidence/truth-validation-fixture/FIND-QUICK-001.json"] : [],
      summary: boundIntake.policy.quick_dynamic.enabled && finding.finding_id === "FIND-QUICK-001"
        ? "授权的本机应用路径产生了可复查的非破坏性验证证据。"
        : "该发现不满足本次快速动态验证条件，已转入静态三方复核。",
      gaps: [],
    })),
  });
}

function review(role, boundIntake, quickResult, verdict) {
  const ids = quickResult.results.filter(item => item.status !== "CONFIRMED").map(item => item.finding_id);
  return seal({
    schema_version: 1,
    artifact_type: "static-truth-review",
    audit_id: boundIntake.audit_id,
    round: boundIntake.round,
    role,
    execution_status: ids.length > 0 ? "COMPLETE" : "NOT_APPLICABLE",
    agent_session_id: ids.length > 0 ? `${role.toLowerCase()}-fixture-r1` : null,
    intake_digest: boundIntake.artifact_digest,
    quick_result_digest: quickResult.artifact_digest,
    ...(role === "NEGATIVE" ? { affirmative_review_digest: null } : {}),
    ...(role === "MODERATOR" ? { affirmative_review_digest: null, negative_review_digest: null } : {}),
    reviewed_finding_ids: ids,
    findings: ids.map(findingId => ({
      finding_id: findingId,
      verdict,
      claims: ["已独立核对入口、数据流、保护措施与安全影响。"],
      evidence_refs: ["reports/adjudication/finding-input.truth-validation-fixture.r1.json"],
      reasoning: "冻结源码与双方证据支持当前角色结论，且未发现未解释的摘要漂移。",
      gaps: [],
    })),
  });
}

function routing(boundIntake, quickResult, affirmative, negative, moderator) {
  const moderatorById = new Map(moderator.findings.map(item => [item.finding_id, item]));
  const findings = quickResult.results.map(result => {
    const finalVerdict = result.status === "CONFIRMED" ? "TRUE_POSITIVE" : moderatorById.get(result.finding_id).verdict;
    return {
      finding_id: result.finding_id,
      route: result.status === "CONFIRMED" ? "QUICK_DYNAMIC" : "STATIC_THREE_PARTY",
      quick_dynamic_status: result.status,
      moderator_verdict: result.status === "CONFIRMED" ? null : finalVerdict,
      final_verdict: finalVerdict,
      report_disposition: finalVerdict === "TRUE_POSITIVE" ? "FINDING" : finalVerdict === "FALSE_POSITIVE" ? "EXCLUDED" : "RESIDUAL_GAP",
      evidence_refs: result.evidence_refs,
      rationale: result.status === "CONFIRMED" ? "快速动态证据满足确认门槛。" : "本地三方已完成证据挑战并由主持人作出终局裁定。",
    };
  });
  return seal({
    schema_version: 1,
    artifact_type: "finding-validation-routing-manifest",
    audit_id: boundIntake.audit_id,
    round: boundIntake.round,
    scope_digest: boundIntake.scope_digest,
    intake_digest: boundIntake.artifact_digest,
    quick_result_digest: quickResult.artifact_digest,
    role_review_digests: {
      affirmative: affirmative.artifact_digest,
      negative: negative.artifact_digest,
      moderator: moderator.artifact_digest,
    },
    full_dynamic_trigger: "MANUAL_ONLY",
    findings,
    summary: {
      total: findings.length,
      true_positive: findings.filter(item => item.final_verdict === "TRUE_POSITIVE").length,
      false_positive: findings.filter(item => item.final_verdict === "FALSE_POSITIVE").length,
      inconclusive: findings.filter(item => item.final_verdict === "INCONCLUSIVE").length,
    },
    complete: true,
  });
}

const validIntake = intake(true);
const validQuick = quick(validIntake);
const affirmative = review("AFFIRMATIVE", validIntake, validQuick, "PROVEN");
const negative = review("NEGATIVE", validIntake, validQuick, "REFUTED");
negative.affirmative_review_digest = affirmative.artifact_digest;
negative.artifact_digest = truthValidationArtifactDigest(negative);
const moderator = review("MODERATOR", validIntake, validQuick, "TRUE_POSITIVE");
moderator.affirmative_review_digest = affirmative.artifact_digest;
moderator.negative_review_digest = negative.artifact_digest;
moderator.artifact_digest = truthValidationArtifactDigest(moderator);
const validRouting = routing(validIntake, validQuick, affirmative, negative, moderator);
const bundle = { intake: validIntake, quickResultSet: validQuick, affirmative, negative, moderator, routing: validRouting };

assert.deepEqual(validateTruthValidationIntake(validIntake), []);
assert.equal(validIntake.findings[1].quick_dynamic_eligible, true);
assert.equal(validIntake.findings[1].runtime_request_path, null);
assert.deepEqual(validateQuickDynamicResultSet(validQuick, validIntake), []);
assert.deepEqual(validateStaticRoleReview(affirmative, { intake: validIntake, quickResultSet: validQuick, role: "AFFIRMATIVE" }), []);
assert.deepEqual(validateValidationRoutingManifest(validRouting, bundle), []);
assert.deepEqual(validateTruthValidationBundle(bundle), []);

const remote = structuredClone(validQuick);
remote.results[0].target_origin = "https://example.com";
remote.artifact_digest = truthValidationArtifactDigest(remote);
assert(validateQuickDynamicResultSet(remote, validIntake).some(error => error.includes("target-origin-invalid")));

const missingStatic = structuredClone(moderator);
missingStatic.findings = [];
missingStatic.artifact_digest = truthValidationArtifactDigest(missingStatic);
assert(validateStaticRoleReview(missingStatic, { intake: validIntake, quickResultSet: validQuick, role: "MODERATOR" }).some(error => error.includes("missing")));

const englishNarrative = structuredClone(affirmative);
englishNarrative.findings[0].claims = ["English-only claim is not a Chinese deliverable."];
englishNarrative.artifact_digest = truthValidationArtifactDigest(englishNarrative);
assert(validateStaticRoleReview(englishNarrative, { intake: validIntake, quickResultSet: validQuick, role: "AFFIRMATIVE" })
  .some(error => error.includes("narrative-not-chinese")));

const wrongRouting = structuredClone(validRouting);
wrongRouting.findings[1].final_verdict = "FALSE_POSITIVE";
wrongRouting.findings[1].report_disposition = "EXCLUDED";
wrongRouting.artifact_digest = truthValidationArtifactDigest(wrongRouting);
assert(validateValidationRoutingManifest(wrongRouting, { ...bundle, routing: wrongRouting }).some(error => error.includes("static-route-invalid")));

const staleModerator = structuredClone(moderator);
staleModerator.negative_review_digest = "d".repeat(64);
staleModerator.artifact_digest = truthValidationArtifactDigest(staleModerator);
assert(validateTruthValidationBundle({ ...bundle, moderator: staleModerator }).some(error => error.includes("moderator:negative-review-binding-invalid")));

const sameSessionNegative = structuredClone(negative);
sameSessionNegative.agent_session_id = affirmative.agent_session_id;
sameSessionNegative.artifact_digest = truthValidationArtifactDigest(sameSessionNegative);
const sameSessionModerator = structuredClone(moderator);
sameSessionModerator.negative_review_digest = sameSessionNegative.artifact_digest;
sameSessionModerator.artifact_digest = truthValidationArtifactDigest(sameSessionModerator);
assert(validateTruthValidationBundle({ ...bundle, negative: sameSessionNegative, moderator: sameSessionModerator })
  .includes("static-role-session-not-distinct"));

const disabledIntake = intake(false);
const disabledQuick = quick(disabledIntake);
assert(disabledQuick.results.every(item => item.status === "SKIPPED"));
assert.deepEqual(validateQuickDynamicResultSet(disabledQuick, disabledIntake), []);

const cliWorkspace = await mkdtemp(join(tmpdir(), "truth-validation-cli-"));
try {
  await Promise.all([
    mkdir(join(cliWorkspace, "reports/adjudication"), { recursive: true }),
    mkdir(join(cliWorkspace, "reports/stage-deliveries/truth-validation-cli-fixture/sets"), { recursive: true }),
    mkdir(join(cliWorkspace, "reports/validation/static/truth-validation-cli-fixture"), { recursive: true }),
  ]);
  const candidateInput = {
    schema_version: 1,
    audit_id: "truth-validation-cli-fixture",
    scope_digest: DIGEST,
    plan_digest: "b".repeat(64),
    structural_digest: "c".repeat(64),
    candidates: [],
  };
  candidateInput.manifest_digest = candidateManifestDigest(candidateInput);
  const adjudication = {
    schema_version: 1,
    audit_id: candidateInput.audit_id,
    scope_digest: candidateInput.scope_digest,
    input_manifest_digest: candidateInput.manifest_digest,
    adjudicator_session_id: "truth-validation-cli-adjudicator-r1",
    decisions: [],
  };
  adjudication.manifest_digest = candidateManifestDigest(adjudication);
  const requestSet = {
    schema_version: 1,
    set_type: "external-runtime-validation-request-set",
    audit_id: candidateInput.audit_id,
    round: 1,
    scope_digest: candidateInput.scope_digest,
    items: [],
    item_count: 0,
  };
  requestSet.set_digest = artifactSetDigest(requestSet);
  const candidatePath = join(cliWorkspace, "reports/adjudication/finding-input.json");
  const adjudicationPath = join(cliWorkspace, "reports/adjudication/finding-adjudication.json");
  const requestSetPath = join(cliWorkspace, "reports/stage-deliveries/truth-validation-cli-fixture/sets/runtime-validation-requests.r1.json");
  await Promise.all([
    writeFile(candidatePath, `${JSON.stringify(candidateInput, null, 2)}\n`),
    writeFile(adjudicationPath, `${JSON.stringify(adjudication, null, 2)}\n`),
    writeFile(requestSetPath, `${JSON.stringify(requestSet, null, 2)}\n`),
  ]);
  const cliEnvironment = { AUDIT_WORKSPACE_ROOT: cliWorkspace, AUDIT_QUICK_DYNAMIC_ENABLED: "false" };
  runScript("build-truth-validation-intake.mjs", [
    "--candidate-input", "reports/adjudication/finding-input.json",
    "--adjudication", "reports/adjudication/finding-adjudication.json",
    "--runtime-request-set", "reports/stage-deliveries/truth-validation-cli-fixture/sets/runtime-validation-requests.r1.json",
    "--round", "1",
    "--output", "reports/validation/truth-validation-intake.truth-validation-cli-fixture.r1.json",
  ], { cwd: cliWorkspace, environment: cliEnvironment });
  const cliIntakePath = join(cliWorkspace, "reports/validation/truth-validation-intake.truth-validation-cli-fixture.r1.json");
  const cliIntake = JSON.parse(await readFile(cliIntakePath, "utf8"));
  assert.deepEqual(validateTruthValidationIntake(cliIntake), []);
  runScript("run-quick-dynamic-validation.mjs", [
    "--intake", "reports/validation/truth-validation-intake.truth-validation-cli-fixture.r1.json",
    "--output", "reports/validation/quick/truth-validation-cli-fixture.r1.json",
  ], { cwd: cliWorkspace, environment: cliEnvironment });
  const cliQuickPath = join(cliWorkspace, "reports/validation/quick/truth-validation-cli-fixture.r1.json");
  const cliQuick = JSON.parse(await readFile(cliQuickPath, "utf8"));
  assert.deepEqual(validateQuickDynamicResultSet(cliQuick, cliIntake), []);
  const cliAffirmative = review("AFFIRMATIVE", cliIntake, cliQuick, "PROVEN");
  const cliNegative = review("NEGATIVE", cliIntake, cliQuick, "REFUTED");
  cliNegative.affirmative_review_digest = cliAffirmative.artifact_digest;
  cliNegative.artifact_digest = truthValidationArtifactDigest(cliNegative);
  const cliModerator = review("MODERATOR", cliIntake, cliQuick, "TRUE_POSITIVE");
  cliModerator.affirmative_review_digest = cliAffirmative.artifact_digest;
  cliModerator.negative_review_digest = cliNegative.artifact_digest;
  cliModerator.artifact_digest = truthValidationArtifactDigest(cliModerator);
  const cliAffirmativePath = join(cliWorkspace, "reports/validation/static/truth-validation-cli-fixture/affirmative.r1.json");
  const cliNegativePath = join(cliWorkspace, "reports/validation/static/truth-validation-cli-fixture/negative.r1.json");
  const cliModeratorPath = join(cliWorkspace, "reports/validation/static/truth-validation-cli-fixture/moderator.r1.json");
  await Promise.all([
    writeFile(cliAffirmativePath, `${JSON.stringify(cliAffirmative, null, 2)}\n`),
    writeFile(cliNegativePath, `${JSON.stringify(cliNegative, null, 2)}\n`),
    writeFile(cliModeratorPath, `${JSON.stringify(cliModerator, null, 2)}\n`),
  ]);
  const routingPath = join(cliWorkspace, "reports/validation/validation-routing.truth-validation-cli-fixture.r1.json");
  const routingArgs = [
    "--intake", cliIntakePath,
    "--quick", cliQuickPath,
    "--affirmative", cliAffirmativePath,
    "--negative", cliNegativePath,
    "--moderator", cliModeratorPath,
  ];
  runScript("build-validation-routing.mjs", [...routingArgs, "--output", routingPath], { cwd: cliWorkspace, environment: cliEnvironment });
  runScript("validate-truth-validation.mjs", [...routingArgs, "--routing", routingPath], { cwd: cliWorkspace, environment: cliEnvironment });
  runScript("build-validation-routing.mjs", [...routingArgs, "--output", join(cliWorkspace, "routing-escape.json")], {
    cwd: cliWorkspace,
    environment: cliEnvironment,
    expected: 1,
  });
  const cliRouting = JSON.parse(await readFile(routingPath, "utf8"));
  assert.deepEqual(validateTruthValidationBundle({
    intake: cliIntake,
    quickResultSet: cliQuick,
    affirmative: cliAffirmative,
    negative: cliNegative,
    moderator: cliModerator,
    routing: cliRouting,
  }), []);

  const invalidRequestSet = structuredClone(requestSet);
  invalidRequestSet.item_count = 1;
  invalidRequestSet.set_digest = artifactSetDigest(invalidRequestSet);
  await writeFile(requestSetPath, `${JSON.stringify(invalidRequestSet, null, 2)}\n`);
  runScript("build-truth-validation-intake.mjs", [
    "--candidate-input", "reports/adjudication/finding-input.json",
    "--adjudication", "reports/adjudication/finding-adjudication.json",
    "--runtime-request-set", "reports/stage-deliveries/truth-validation-cli-fixture/sets/runtime-validation-requests.r1.json",
    "--round", "1",
    "--output", "reports/validation/invalid-intake.json",
  ], { cwd: cliWorkspace, environment: cliEnvironment, expected: 1 });

  const enabledIntakePath = join(cliWorkspace, "reports/validation/truth-validation-intake.enabled.r1.json");
  const enabledOutputPath = join(cliWorkspace, "reports/validation/quick/enabled.r1.json");
  const rejectedOutputPath = join(cliWorkspace, "reports/validation/quick/rejected.r1.json");
  const missingEvidenceOutputPath = join(cliWorkspace, "reports/validation/quick/missing-evidence.r1.json");
  const contextPath = join(cliWorkspace, "test-environment.txt");
  const contextBytes = Buffer.from("URL: http://127.0.0.1:4173\n", "utf8");
  const fakeOpenCodePath = join(cliWorkspace, "fake-opencode.mjs");
  await Promise.all([
    writeFile(enabledIntakePath, `${JSON.stringify(validIntake, null, 2)}\n`),
    writeFile(contextPath, contextBytes, { mode: 0o600 }),
    writeFile(fakeOpenCodePath, `#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
const intake = JSON.parse(readFileSync(process.env.AUDIT_QUICK_DYNAMIC_INTAKE_PATH, "utf8"));
const remote = process.env.FAKE_QUICK_MODE === "remote";
const missing = process.env.FAKE_QUICK_MODE === "missing";
const evidencePath = \`reports/validation/quick/evidence/\${intake.audit_id}/\${missing ? "missing" : "fixture"}.json\`;
const value = {
  schema_version: 1,
  artifact_type: "quick-dynamic-result-set",
  audit_id: intake.audit_id,
  round: intake.round,
  intake_digest: intake.artifact_digest,
  deadline_seconds: 120,
  elapsed_ms: 0,
  deadline_exceeded: false,
  evidence_bindings: [],
  results: intake.findings.map(finding => ({
    finding_id: finding.finding_id,
    status: finding.quick_dynamic_eligible ? "CONFIRMED" : "SKIPPED",
    duration_ms: 0,
    target_origin: finding.quick_dynamic_eligible ? (remote ? "https://example.com" : "http://127.0.0.1:4173") : null,
    evidence_refs: finding.quick_dynamic_eligible ? [evidencePath] : [],
    summary: finding.quick_dynamic_eligible ? "授权的本机应用路径产生了可复查证据。" : "该发现不满足快速动态条件，已转入静态复核。",
    gaps: [],
  })),
  artifact_digest: "0".repeat(64),
};
if (!missing) {
  mkdirSync(join(process.env.AUDIT_WORKSPACE_ROOT, \`reports/validation/quick/evidence/\${intake.audit_id}\`), { recursive: true });
  writeFileSync(join(process.env.AUDIT_WORKSPACE_ROOT, evidencePath), "{}\\n");
}
mkdirSync(dirname(process.env.AUDIT_QUICK_DYNAMIC_RESULT_PATH), { recursive: true });
writeFileSync(process.env.AUDIT_QUICK_DYNAMIC_RESULT_PATH, JSON.stringify(value));
`),
  ]);
  await chmod(fakeOpenCodePath, 0o700);
  const enabledEnvironment = {
    AUDIT_WORKSPACE_ROOT: cliWorkspace,
    AUDIT_QUICK_DYNAMIC_ENABLED: "true",
    AUDIT_TEST_ENVIRONMENT_CONTEXT_PATH: contextPath,
    AUDIT_TEST_ENVIRONMENT_CONTEXT_SHA256: createHash("sha256").update(contextBytes).digest("hex"),
    AUDIT_OPENCODE_COMMAND: fakeOpenCodePath,
  };
  runScript("run-quick-dynamic-validation.mjs", [
    "--intake", "reports/validation/truth-validation-intake.enabled.r1.json",
    "--output", "reports/validation/quick/enabled.r1.json",
  ], { cwd: cliWorkspace, environment: enabledEnvironment });
  const enabledResult = JSON.parse(await readFile(enabledOutputPath, "utf8"));
  assert.deepEqual(validateQuickDynamicResultSet(enabledResult, validIntake), []);
  assert.equal(enabledResult.results[0].status, "CONFIRMED");
  assert.notEqual(enabledResult.artifact_digest, "0".repeat(64));
  assert.equal(enabledResult.evidence_bindings[0].sha256, createHash("sha256").update("{}\n").digest("hex"));

  runScript("run-quick-dynamic-validation.mjs", [
    "--intake", "reports/validation/truth-validation-intake.enabled.r1.json",
    "--output", "reports/validation/quick/rejected.r1.json",
  ], { cwd: cliWorkspace, environment: { ...enabledEnvironment, FAKE_QUICK_MODE: "remote" } });
  const rejectedResult = JSON.parse(await readFile(rejectedOutputPath, "utf8"));
  assert.deepEqual(validateQuickDynamicResultSet(rejectedResult, validIntake), []);
  assert.equal(rejectedResult.results[0].status, "BLOCKED");

  runScript("run-quick-dynamic-validation.mjs", [
    "--intake", "reports/validation/truth-validation-intake.enabled.r1.json",
    "--output", "reports/validation/quick/missing-evidence.r1.json",
  ], { cwd: cliWorkspace, environment: { ...enabledEnvironment, FAKE_QUICK_MODE: "missing" } });
  const missingEvidenceResult = JSON.parse(await readFile(missingEvidenceOutputPath, "utf8"));
  assert.deepEqual(validateQuickDynamicResultSet(missingEvidenceResult, validIntake), []);
  assert.equal(missingEvidenceResult.results[0].status, "BLOCKED");
} finally {
  await rm(cliWorkspace, { recursive: true, force: true });
}

process.stdout.write(`${JSON.stringify({ complete: true, contract: "truth-validation-v1", cases: 23 })}\n`);
