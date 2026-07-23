#!/usr/bin/env node

import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPOSITORY = resolve(HERE, "../..");
const SCRIPTS = resolve(REPOSITORY, ".opencode/skills/common-subagent/audit-coverage-accounting/scripts");
const AUDIT_ID = "semantic-coverage-fixture";
const SCOPE_DIGEST = "a".repeat(64);
const LENSES = ["sink-driven", "control-driven", "config-driven"];

function run(script, args, expectedStatus = 0) {
  const result = spawnSync(process.execPath, [resolve(SCRIPTS, script), ...args], { encoding: "utf8" });
  if (result.status !== expectedStatus) throw new Error(`${script} returned ${result.status}, expected ${expectedStatus}\n${result.stderr}\n${result.stdout}`);
  return result;
}

function objectDigest(value, field) {
  const copy = { ...value };
  delete copy[field];
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

function bytesDigest(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function writeSemanticInputs(directory) {
  const threatPath = join(directory, "threat-model.json");
  const focusPath = join(directory, "focus-areas.json");
  await writeFile(threatPath, `${JSON.stringify({
    schema_version: 1,
    audit_id: AUDIT_ID,
    scope_digest: SCOPE_DIGEST,
    mode: "bootstrap-then-interview",
    system_context: "A small semantic verification fixture.",
    assets: [{ asset_id: "ASSET-001", name: "sensitive record", sensitivity: "high", evidence: [{ fixture: true }] }],
    actors: [{ actor_id: "ACTOR-001", type: "remote_auth", capabilities: ["call API"], evidence: [{ fixture: true }] }],
    trust_boundaries: [{ trust_boundary_id: "TB-001", from: "tenant request", to: "service", evidence: [{ fixture: true }] }],
    entry_points: [{ entry_point_id: "EP-001", name: "tenant API", trust_boundary_ids: ["TB-001"], reachable_asset_ids: ["ASSET-001"], inventory_ids: ["entry-1"], evidence: [{ fixture: true }] }],
    threats: [{ threat_id: "T-001", outcome: "Authenticated tenant reads another tenant sensitive record", actor_ids: ["ACTOR-001"], entry_point_ids: ["EP-001"], trust_boundary_ids: ["TB-001"], asset_ids: ["ASSET-001"], dimensions: ["D3"], impact: "high", likelihood: "possible", status: "partially_mitigated", controls: ["ownership check"], evidence: [{ fixture: true }], provenance_tags: ["code-verified", "owner-asserted"] }],
    deprioritized: [],
    history_clusters: [{ cluster_id: "HC-001", entry_point_ids: ["EP-001"], weakness_class: "cross-tenant access", asset_ids: ["ASSET-001"], evidence: [{ fixture: true }], sibling_locations: ["src/TenantApi.java"] }],
    entry_point_coverage: [{ entry_point_id: "EP-001", status: "THREAT", threat_ids: ["T-001"], reason: null, evidence: [{ fixture: true }] }],
    open_questions: [{ question_id: "Q-001", question: "Is the gateway tenant-aware?", blocking: true, status: "resolved", evidence: [{ owner_answer: "yes" }] }],
    provenance: { target: "fixture", commit: "abc123", inputs: ["fixture"], owner: "test-owner" },
  }, null, 2)}\n`, "utf8");
  run("seal-semantic-manifest.mjs", ["--input", threatPath]);
  const threat = JSON.parse(await readFile(threatPath, "utf8"));
  await writeFile(focusPath, `${JSON.stringify({
    schema_version: 1,
    audit_id: AUDIT_ID,
    scope_digest: SCOPE_DIGEST,
    threat_model_digest: threat.manifest_digest,
    required_lenses: LENSES,
    focus_areas: [{
      focus_area_id: "FA-001",
      title: "Tenant object access",
      description: "Tenant request through ownership enforcement to a sensitive record.",
      priority: "high",
      entry_point_ids: ["EP-001"],
      threat_ids: ["T-001"],
      trust_boundary_ids: ["TB-001"],
      asset_ids: ["ASSET-001"],
      history_cluster_ids: ["HC-001"],
      required_discovery_tracks: ["coverage", "blind", "seeded-variant"],
      assignments: [{
        assignment_id: "FA-001-java-base",
        agent_name: "java-source-auditor",
        language: "java",
        file_function_domain: "base",
        catalog_domain: "java",
        file_ids: ["file:001"],
        function_ids: ["function:001"],
        catalog_ids: ["JW-AUTHZ-01"],
      }, {
        assignment_id: "FA-001-ai-ai",
        agent_name: "ai-security-auditor",
        language: "ai",
        file_function_domain: "ai",
        catalog_domain: "ai",
        file_ids: ["file:001"],
        function_ids: ["function:001"],
        catalog_ids: [],
      }],
      context_file_ids: [],
      context_function_ids: [],
    }],
    gaps: [],
  }, null, 2)}\n`, "utf8");
  run("seal-semantic-manifest.mjs", ["--input", focusPath]);
  return { threatPath, focusPath, threat: JSON.parse(await readFile(threatPath, "utf8")), focus: JSON.parse(await readFile(focusPath, "utf8")) };
}

async function writeSnapshot(path, threatPath, focusPath, threat, focus) {
  const structuralDir = dirname(path);
  const scopePath = join(structuralDir, "scope.json");
  const functionsPath = join(structuralDir, "functions-java.json");
  const catalogPath = join(structuralDir, "catalog.json");
  await writeFile(scopePath, `${JSON.stringify({ audit_id: AUDIT_ID, scope_digest: SCOPE_DIGEST, files: [{ file_id: "file:001", path: "src/TenantApi.java", review_required: true, owner_agent: "java-source-auditor" }] }, null, 2)}\n`, "utf8");
  await writeFile(functionsPath, `${JSON.stringify({ audit_id: AUDIT_ID, scope_digest: SCOPE_DIGEST, language: "java", functions: [{ function_id: "function:001", path: "src/TenantApi.java", qualified_name: "TenantApi.get", owner_agent: "java-source-auditor" }] }, null, 2)}\n`, "utf8");
  await writeFile(catalogPath, `${JSON.stringify({ profile_id: "semantic-fixture", entries: [{ id: "JW-AUTHZ-01", applies_to: ["java"] }] }, null, 2)}\n`, "utf8");
  const threatBytes = await readFile(threatPath);
  const focusBytes = await readFile(focusPath);
  const snapshot = {
    schema_version: 1,
    audit_id: AUDIT_ID,
    scope_digest: SCOPE_DIGEST,
    scope: { path: scopePath, sha256: bytesDigest(await readFile(scopePath)) },
    functions: [{ language: "java", path: functionsPath, sha256: bytesDigest(await readFile(functionsPath)) }],
    catalog: { path: catalogPath, sha256: bytesDigest(await readFile(catalogPath)) },
    semantic: {
      threat_model: { path: threatPath, manifest_digest: threat.manifest_digest, sha256: bytesDigest(threatBytes) },
      focus_areas: { path: focusPath, manifest_digest: focus.manifest_digest, sha256: bytesDigest(focusBytes) },
    },
  };
  snapshot.snapshot_digest = objectDigest(snapshot, "snapshot_digest");
  await writeFile(path, `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
}

async function writeReports(directory) {
  await mkdir(directory, { recursive: true });
  for (const assignment of [
    { agent: "java-source-auditor", language: "java", catalog: ["JW-AUTHZ-01"] },
    { agent: "ai-security-auditor", language: "ai", catalog: [] },
  ]) {
    for (const lens of LENSES) {
      const report = {
        schema_version: 1,
        audit_id: AUDIT_ID,
        round: 1,
        agent_name: assignment.agent,
        agent_session_id: `${assignment.language}-fa-001-${lens}-coverage-r1`,
        scope_digest: SCOPE_DIGEST,
        focus_area_id: "FA-001",
        discovery_track: "coverage",
        audit_strategy: lens,
        review_depth: { files_read: ["src/TenantApi.java"], functions_read: ["TenantApi.get"] },
        scope: { scope_digest: SCOPE_DIGEST, assigned_file_ids: ["file:001"], assigned_function_ids: ["function:001"], assigned_catalog_ids: assignment.catalog },
      };
      await writeFile(join(directory, `${assignment.agent}.${lens}.audit-report.json`), `${JSON.stringify(report, null, 2)}\n`, "utf8");
    }
  }
  for (const track of ["blind", "seeded-variant"]) {
    const report = {
      schema_version: 1,
      audit_id: AUDIT_ID,
      round: 1,
      agent_name: "java-source-auditor",
      agent_session_id: `java-fa-001-${track}-r1`,
      scope_digest: SCOPE_DIGEST,
      focus_area_id: "FA-001",
      discovery_track: track,
      entry_point_ids: ["EP-001"],
      threat_ids: ["T-001"],
      files_read: ["src/TenantApi.java"],
      functions_read: ["TenantApi.get"],
      hypotheses_tested: [track === "blind" ? "alternate tenant identity flow" : "same-class sibling endpoint"],
      seed_inputs: track === "blind" ? [] : ["HC-001"],
      status: "PASS",
      evidence: [{ fixture: track }],
      findings: [],
      gaps: [],
    };
    await writeFile(join(directory, `java-source-auditor.${track}.discovery.json`), `${JSON.stringify(report, null, 2)}\n`, "utf8");
  }
}

async function writeAttack(path, threat, focus, overrides = {}) {
  const report = {
    schema_version: 1,
    audit_id: AUDIT_ID,
    round: 1,
    agent_name: "security-attack-chain-hunter",
    scope_digest: SCOPE_DIGEST,
    threat_model_digest: threat.manifest_digest,
    focus_areas_digest: focus.manifest_digest,
    status: "PASS",
    reviewed_focus_area_ids: ["FA-001"],
    reviewed_trust_boundary_ids: ["TB-001"],
    reviewed_asset_ids: ["ASSET-001"],
    evidence: [{ fixture: "system-pass" }],
    chain_candidates: [],
    gaps: [],
    ...overrides,
  };
  await writeFile(path, `${JSON.stringify(report, null, 2)}\n`, "utf8");
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "opencode-semantic-coverage-test-"));
  try {
    const inputs = join(work, "inputs");
    const reports = join(work, "reports");
    const negativeReports = join(work, "reports-negative");
    const snapshotPath = join(work, "snapshot-index.json");
    const attackPath = join(work, "attack-chain.json");
    const outputPath = join(work, "semantic-positive.json");
    await mkdir(inputs, { recursive: true });
    const { threatPath, focusPath, threat, focus } = await writeSemanticInputs(inputs);
    await writeSnapshot(snapshotPath, threatPath, focusPath, threat, focus);
    await writeReports(reports);
    await writeAttack(attackPath, threat, focus);

    const commonArgs = ["--audit-id", AUDIT_ID, "--snapshot-index", snapshotPath, "--attack-chain-report", attackPath];
    run("verify-semantic-coverage.mjs", [...commonArgs, "--reports-dir", reports, "--output", outputPath]);
    const positive = JSON.parse(await readFile(outputPath, "utf8"));
    if (!positive.complete || positive.expected.focus_assignment_lens_sessions !== 6 || positive.expected.primary_assignments !== 5) throw new Error("Positive semantic coverage fixture did not verify");

    await cp(reports, negativeReports, { recursive: true });
    await unlink(join(negativeReports, "java-source-auditor.control-driven.audit-report.json"));
    const missingLensOutput = join(work, "semantic-missing-lens.json");
    run("verify-semantic-coverage.mjs", [...commonArgs, "--reports-dir", negativeReports, "--output", missingLensOutput], 2);
    const missingLens = JSON.parse(await readFile(missingLensOutput, "utf8"));
    if (missingLens.complete || !missingLens.missing.focus_lenses.some(item => item.lens === "control-driven")) throw new Error("Missing Focus Area lens was not detected");

    const incompleteAttackPath = join(work, "attack-chain-incomplete.json");
    await writeAttack(incompleteAttackPath, threat, focus, { reviewed_asset_ids: [] });
    const attackOutput = join(work, "semantic-attack-gap.json");
    run("verify-semantic-coverage.mjs", ["--audit-id", AUDIT_ID, "--snapshot-index", snapshotPath, "--reports-dir", reports, "--attack-chain-report", incompleteAttackPath, "--output", attackOutput], 2);
    const attackGap = JSON.parse(await readFile(attackOutput, "utf8"));
    if (attackGap.complete || !attackGap.missing.attack_chain.some(item => item.field === "reviewed_asset_ids")) throw new Error("Missing attack-chain asset coverage was not detected");

    const focusMissingPath = join(work, "focus-areas-missing-primary.json");
    const focusMissing = JSON.parse(JSON.stringify(focus));
    delete focusMissing.manifest_digest;
    focusMissing.focus_areas[0].assignments = focusMissing.focus_areas[0].assignments.filter(item => item.agent_name !== "ai-security-auditor");
    await writeFile(focusMissingPath, `${JSON.stringify(focusMissing, null, 2)}\n`, "utf8");
    run("seal-semantic-manifest.mjs", ["--input", focusMissingPath]);
    const sealedFocusMissing = JSON.parse(await readFile(focusMissingPath, "utf8"));
    const missingPrimarySnapshot = join(work, "snapshot-missing-primary.json");
    const missingPrimaryAttack = join(work, "attack-missing-primary.json");
    await writeSnapshot(missingPrimarySnapshot, threatPath, focusMissingPath, threat, sealedFocusMissing);
    await writeAttack(missingPrimaryAttack, threat, sealedFocusMissing);
    const missingPrimaryOutput = join(work, "semantic-missing-primary.json");
    run("verify-semantic-coverage.mjs", ["--audit-id", AUDIT_ID, "--snapshot-index", missingPrimarySnapshot, "--reports-dir", reports, "--attack-chain-report", missingPrimaryAttack, "--output", missingPrimaryOutput], 2);
    const missingPrimary = JSON.parse(await readFile(missingPrimaryOutput, "utf8"));
    if (missingPrimary.complete || !missingPrimary.missing.primary_assignments.some(item => item.key.includes("ai-security-auditor|ai|file|file:001"))) throw new Error("Missing AI primary Focus Area assignment was not detected");

    process.stdout.write(`${JSON.stringify({ complete: true, threat_model_sealed: true, focus_areas_sealed: true, primary_assignments_verified: 5, focus_lenses_verified: 6, blind_track_verified: true, seeded_variant_verified: true, missing_focus_lens_caught: "control-driven", missing_attack_chain_asset_caught: "ASSET-001", missing_ai_primary_assignment_caught: "file:001" })}\n`);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
