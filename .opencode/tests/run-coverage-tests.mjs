#!/usr/bin/env node

import { cp, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { catalogQuestionDigest, deriveCoverageCells } from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-cell-accounting.mjs";
import {
  finalizeLedger,
  initializeLedger,
  inspectSubject,
  recordToolResult,
  submitDecision,
  verifyLedger,
} from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-ledger-core.mjs";
import { objectDigest, sha256, validatePlan } from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-v2-common.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPOSITORY = resolve(HERE, "../..");
const SCRIPTS = resolve(REPOSITORY, ".opencode/skills/common-subagent/audit-coverage-accounting/scripts");
const CATALOG = resolve(REPOSITORY, ".opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json");
const FIXTURE = resolve(HERE, "coverage-fixture");
const MALFORMED_JS_FIXTURE = resolve(HERE, "malformed-js-fixture");
const AUDIT_ID = "coverage-fixture-audit";
const LENSES = ["sink-driven", "control-driven", "config-driven"];
const DIMENSIONS = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);
const DOMAIN_AGENT = { java: "java-source-auditor", web: "web-source-auditor", platform: "platform-security-auditor", ai: "ai-security-auditor" };

async function makeSemanticManifests(directory, scope, manifests, catalog) {
  const threatModelPath = join(directory, "threat-model.json");
  const focusAreasPath = join(directory, "focus-areas.json");
  await writeFile(threatModelPath, `${JSON.stringify({
    schema_version: 1,
    audit_id: AUDIT_ID,
    scope_digest: scope.scope_digest,
    mode: "bootstrap",
    system_context: "Coverage fixture with one reachable test entry point.",
    assets: [{ asset_id: "ASSET-001", name: "fixture integrity", sensitivity: "high", evidence: [{ fixture: true }] }],
    actors: [{ actor_id: "ACTOR-001", type: "remote_unauth", capabilities: ["supply fixture input"], evidence: [{ fixture: true }] }],
    trust_boundaries: [{ trust_boundary_id: "TB-001", from: "fixture input", to: "test code", evidence: [{ fixture: true }] }],
    entry_points: [{ entry_point_id: "EP-001", name: "fixture entry", trust_boundary_ids: ["TB-001"], reachable_asset_ids: ["ASSET-001"], inventory_ids: ["fixture-entry"], evidence: [{ fixture: true }] }],
    threats: [{ threat_id: "T-001", outcome: "Attacker-controlled fixture input compromises test integrity", actor_ids: ["ACTOR-001"], entry_point_ids: ["EP-001"], trust_boundary_ids: ["TB-001"], asset_ids: ["ASSET-001"], dimensions: ["D1"], impact: "high", likelihood: "possible", status: "unmitigated", controls: [], evidence: [{ fixture: true }], provenance_tags: ["code-verified"] }],
    deprioritized: [],
    history_clusters: [],
    entry_point_coverage: [{ entry_point_id: "EP-001", status: "THREAT", threat_ids: ["T-001"], reason: null, evidence: [{ fixture: true }] }],
    open_questions: [],
    provenance: { target: "coverage-fixture", commit: "fixture", inputs: ["test"], owner: null },
  }, null, 2)}\n`, "utf8");
  run("seal-semantic-manifest.mjs", ["--input", threatModelPath]);
  const threatModel = JSON.parse(await readFile(threatModelPath, "utf8"));
  const functions = manifests.flatMap(manifest => manifest.functions);
  const assignments = Object.entries(DOMAIN_AGENT).map(([domain, agent]) => {
    const isAi = domain === "ai";
    return {
      assignment_id: `FA-001-${domain}-${isAi ? "ai" : "base"}`,
      agent_name: agent,
      language: domain,
      file_function_domain: isAi ? "ai" : "base",
      catalog_domain: domain,
      file_ids: scope.files.filter(file => file.review_required && (isAi || file.owner_agent === agent)).map(file => file.file_id),
      function_ids: functions.filter(fn => isAi || fn.owner_agent === agent).map(fn => fn.function_id),
      catalog_ids: catalog.entries.filter(entry => entry.applies_to.includes(domain)).map(entry => entry.id),
    };
  }).filter(assignment => assignment.file_ids.length + assignment.function_ids.length + assignment.catalog_ids.length > 0);
  await writeFile(focusAreasPath, `${JSON.stringify({
    schema_version: 1,
    audit_id: AUDIT_ID,
    scope_digest: scope.scope_digest,
    threat_model_digest: threatModel.manifest_digest,
    required_lenses: LENSES,
    focus_areas: [{
      focus_area_id: "FA-001",
      title: "Fixture focus",
      description: "All fixture entities in one deterministic Focus Area.",
      priority: "high",
      entry_point_ids: ["EP-001"],
      threat_ids: ["T-001"],
      trust_boundary_ids: ["TB-001"],
      asset_ids: ["ASSET-001"],
      history_cluster_ids: [],
      required_discovery_tracks: ["coverage", "blind"],
      assignments,
      context_file_ids: [],
      context_function_ids: [],
    }],
    gaps: [],
  }, null, 2)}\n`, "utf8");
  run("seal-semantic-manifest.mjs", ["--input", focusAreasPath]);
  return { threatModelPath, focusAreasPath };
}

function run(script, args, expectedStatus = 0) {
  const result = spawnSync(process.execPath, [resolve(SCRIPTS, script), ...args], {
    encoding: "utf8",
    maxBuffer: 128 * 1024 * 1024,
  });
  if (result.status !== expectedStatus) {
    throw new Error(`${script} returned ${result.status}, expected ${expectedStatus}\n${result.stderr}\n${result.stdout}`);
  }
  return result;
}

function runCommand(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.status !== 0) throw new Error(`${command} failed (${result.status})\n${result.stderr}\n${result.stdout}`);
  return result;
}

async function expectReject(operation, messagePattern) {
  try {
    await operation();
  } catch (error) {
    if (!messagePattern || messagePattern.test(error.message)) return error;
    throw new Error(`Operation failed for the wrong reason: ${error.message}`);
  }
  throw new Error("Expected operation to fail");
}

async function makeReports(directory, scope, manifests, catalog) {
  await mkdir(directory, { recursive: true });
  const functions = manifests.flatMap(manifest => manifest.functions);
  const activeDomains = Object.keys(DOMAIN_AGENT).filter(domain => domain === "ai" || scope.files.some(file => file.owner_agent === DOMAIN_AGENT[domain]));

  for (const domain of activeDomains) {
    const agent = DOMAIN_AGENT[domain];
    const isAiOverlay = domain === "ai";
    const assignedFiles = scope.files.filter(file => file.review_required && (isAiOverlay || file.owner_agent === agent));
    const assignedFunctions = functions.filter(fn => isAiOverlay || fn.owner_agent === agent);
    for (const lens of LENSES) {
      const report = {
        schema_version: 1,
        audit_id: AUDIT_ID,
        round: 1,
        agent_name: agent,
        agent_session_id: `${agent}-${lens}-fixture-session`,
        scope_digest: scope.scope_digest,
        focus_area_id: "FA-001",
        discovery_track: "coverage",
        entry_point_ids: ["EP-001"],
        threat_ids: ["T-001"],
        scope: {
          scope_digest: scope.scope_digest,
          assigned_file_ids: assignedFiles.map(file => file.file_id),
          assigned_function_ids: assignedFunctions.map(fn => fn.function_id),
          assigned_catalog_ids: catalog.entries.filter(entry => entry.applies_to.includes(domain)).map(entry => entry.id),
        },
        language: domain,
        audit_strategy: lens,
        dimensions: DIMENSIONS,
        tool_inputs: [
          { kind: "fixture", scope_digest: scope.scope_digest },
          { kind: "threat-model", scope_digest: scope.scope_digest },
          { kind: "focus-areas", scope_digest: scope.scope_digest, focus_area_id: "FA-001" },
          ...(isAiOverlay ? [{ kind: "ai-surfaces", path: "fixture-ai-surfaces.json", scope_digest: scope.scope_digest }] : []),
        ],
        coverage_cells: [],
        file_coverage: assignedFiles
          .map(file => ({
            file_id: file.file_id,
            domain: isAiOverlay ? "ai" : "base",
            status: "REVIEWED",
            dimensions_reviewed: DIMENSIONS,
            evidence: [file.type === "symlink"
              ? { kind: "symlink-location", file_id: file.file_id, path: file.path, link_target: file.link_target }
              : { kind: "source-location", file_id: file.file_id, path: file.path, sha256: file.sha256, line_start: 1 }],
          })),
        function_coverage: assignedFunctions
          .map(fn => ({ function_id: fn.function_id, domain: isAiOverlay ? "ai" : "base", status: "REVIEWED", dimensions_reviewed: DIMENSIONS, evidence: [{ kind: "function-location", function_id: fn.function_id, path: fn.path, code_sha256: fn.code_sha256, qualified_name: fn.qualified_name, line_start: fn.line_start }] })),
        catalog_coverage: catalog.entries
          .filter(entry => entry.applies_to.includes(domain))
          .map(entry => ({ catalog_id: entry.id, domain, status: "REVIEWED", dimensions_reviewed: entry.dimensions, evidence: [{ kind: "catalog-review", catalog_id: entry.id, domain, lens, catalog_profile: catalog.profile_id, question_sha256: catalogQuestionDigest(entry, lens) }] })),
        findings: [],
        artifacts: [],
        learning_candidates: [],
      };
      report.coverage_cells = deriveCoverageCells(report, new Map(catalog.entries.map(entry => [entry.id, entry])));
      await writeFile(join(directory, `${agent}.${lens}.audit-report.json`), `${JSON.stringify(report, null, 2)}\n`, "utf8");
    }
  }
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "opencode-coverage-test-"));
  try {
    const root = join(work, "fixture");
    const coverage = join(work, "coverage");
    const positiveReports = join(work, "reports-positive");
    const negativeReports = join(work, "reports-negative");
    await cp(FIXTURE, root, { recursive: true });
    await symlink("static/app.js", join(root, "linked-app.js"));
    await mkdir(coverage, { recursive: true });

    const gitScopeRoot = join(work, "git-scope");
    await mkdir(join(gitScopeRoot, "src"), { recursive: true });
    await mkdir(join(gitScopeRoot, "node_modules", "dependency"), { recursive: true });
    await writeFile(join(gitScopeRoot, ".gitignore"), "node_modules/\n", "utf8");
    await writeFile(join(gitScopeRoot, "src", "app.js"), "export const value = 1;\n", "utf8");
    await writeFile(join(gitScopeRoot, "node_modules", "dependency", "index.js"), "module.exports = 1;\n", "utf8");
    runCommand("git", ["-C", gitScopeRoot, "init", "--quiet"]);
    runCommand("git", ["-C", gitScopeRoot, "add", ".gitignore", "src/app.js"]);
    const gitScopePath = join(work, "git-scope.json");
    run("build-scope-manifest.mjs", ["--root", gitScopeRoot, "--audit-id", AUDIT_ID, "--output", gitScopePath]);
    const gitScope = JSON.parse(await readFile(gitScopePath, "utf8"));
    if (gitScope.policy.enumeration !== "git-index-plus-untracked-nonignored"
      || gitScope.files.some(file => file.path.startsWith("node_modules/"))
      || !gitScope.exclusions.some(item => item.path === "node_modules" && item.reason === "gitignore-policy")) {
      throw new Error("Git-aware scope did not prune and record ignored dependency content");
    }

    const scopePath = join(coverage, "scope.json");
    const javaPath = join(coverage, "functions-java.json");
    const jsPath = join(coverage, "functions-javascript.json");
    const embeddedPath = join(coverage, "functions-embedded-web.json");
    const interfacesPath = join(coverage, "interface-manifest.json");
    const interfaceExtractorsPath = join(coverage, "interface-extractor-coverage.json");
    run("build-scope-manifest.mjs", ["--root", root, "--audit-id", AUDIT_ID, "--output", scopePath]);
    run("build-function-manifests.mjs", ["--root", root, "--audit-id", AUDIT_ID, "--scope", scopePath, "--output-dir", coverage, "--jobs", "2"]);
    const cachedBuild = JSON.parse(run("build-function-manifests.mjs", ["--root", root, "--audit-id", AUDIT_ID, "--scope", scopePath, "--output-dir", coverage, "--jobs", "2"]).stdout);
    if (!cachedBuild.manifests.every(manifest => manifest.cached === true)) throw new Error("Digest-bound function manifests were not reused on resume");
    const cachedSourcePath = join(root, "static", "app.js");
    const cachedSource = await readFile(cachedSourcePath, "utf8");
    await writeFile(cachedSourcePath, `${cachedSource}\n// scope drift fixture\n`, "utf8");
    run("build-joern-function-manifest.mjs", ["--root", root, "--audit-id", AUDIT_ID, "--scope", scopePath, "--language", "javascript", "--output", jsPath], 1);
    await writeFile(cachedSourcePath, cachedSource, "utf8");

    const scope = JSON.parse(await readFile(scopePath, "utf8"));
    const manifests = await Promise.all([javaPath, jsPath, embeddedPath].map(async path => JSON.parse(await readFile(path, "utf8"))));
    const catalog = JSON.parse(await readFile(CATALOG, "utf8"));
    run("build-interface-manifest.mjs", ["--root", root, "--audit-id", AUDIT_ID, "--scope", scopePath, "--output", interfacesPath]);
    run("verify-interface-extractors.mjs", ["--audit-id", AUDIT_ID, "--scope", scopePath, "--interfaces", interfacesPath, "--output", interfaceExtractorsPath]);
    const interfaceManifest = JSON.parse(await readFile(interfacesPath, "utf8"));
    const interfaceExtractorCoverage = JSON.parse(await readFile(interfaceExtractorsPath, "utf8"));
    if (!interfaceManifest.complete || !interfaceExtractorCoverage.complete || interfaceManifest.interfaces.length === 0
      || interfaceManifest.interfaces.every(item => item.direction !== "egress")) {
      throw new Error("Deterministic interface extraction did not inventory the fixture egress interface");
    }
    const routingIndexPath = join(coverage, "threat-routing-index.json");
    run("build-threat-routing-index.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      "--functions", javaPath,
      "--functions", jsPath,
      "--functions", embeddedPath,
      "--interfaces", interfacesPath,
      "--interface-extractors", interfaceExtractorsPath,
      "--catalog", CATALOG,
      "--output", routingIndexPath,
    ]);
    const routingIndex = JSON.parse(await readFile(routingIndexPath, "utf8"));
    if (routingIndex.summary.files !== scope.files.length
      || routingIndex.summary.functions !== manifests.flatMap(manifest => manifest.functions).length
      || routingIndex.summary.interfaces !== interfaceManifest.interfaces.length
      || routingIndex.summary.catalog_entries !== catalog.entries.length
      || !routingIndex.catalog.find(item => item.catalog_id.startsWith("JW-"))?.effective_domains.includes("c-cpp")
      || !routingIndex.catalog.find(item => item.catalog_id.startsWith("JW-"))?.effective_domains.includes("python")) {
      throw new Error("Compact threat-routing index does not preserve the complete entity universe");
    }
    const { threatModelPath, focusAreasPath } = await makeSemanticManifests(coverage, scope, manifests, catalog);
    const aiSurfacesPath = join(coverage, "ai-surfaces.json");
    await writeFile(aiSurfacesPath, `${JSON.stringify({
      schema_version: 1,
      audit_id: AUDIT_ID,
      scope_digest: scope.scope_digest,
      items: [],
      gaps: [],
      negative_evidence: [{ kind: "fixture", evidence: "All fixture files remain assigned for explicit AI overlay review." }],
    }, null, 2)}\n`, "utf8");
    const skeletonPath = join(coverage, "java-skeleton.audit-report.json");
    run("initialize-audit-report.mjs", [
      "--audit-id", AUDIT_ID,
      "--round", "1",
      "--agent", "java-source-auditor",
      "--session", "java-sink-r1",
      "--lens", "sink-driven",
      "--language", "java",
      "--scope", scopePath,
      "--functions", javaPath,
      "--functions", jsPath,
      "--functions", embeddedPath,
      "--interfaces", interfacesPath,
      "--interface-extractors", interfaceExtractorsPath,
      "--catalog", CATALOG,
      "--threat-model", threatModelPath,
      "--focus-areas", focusAreasPath,
      "--focus-area", "FA-001",
      "--output", skeletonPath,
    ]);
    const skeleton = JSON.parse(await readFile(skeletonPath, "utf8"));
    if (skeleton.file_coverage.length !== 1 || skeleton.function_coverage.length !== 8 || skeleton.catalog_coverage.length === 0
      || [...skeleton.file_coverage, ...skeleton.function_coverage, ...skeleton.catalog_coverage].some(record => record.status !== "GAP")
      || [...skeleton.file_coverage, ...skeleton.function_coverage].some(record => record.domain !== "base")) {
      throw new Error("Report initializer did not create the exact all-GAP Java matrix");
    }
    run("initialize-audit-report.mjs", [
      "--audit-id", AUDIT_ID,
      "--round", "1",
      "--agent", "ai-security-auditor",
      "--session", "ai-missing-surface-r1",
      "--lens", "sink-driven",
      "--language", "ai",
      "--scope", scopePath,
      "--functions", javaPath,
      "--functions", jsPath,
      "--functions", embeddedPath,
      "--interfaces", interfacesPath,
      "--interface-extractors", interfaceExtractorsPath,
      "--catalog", CATALOG,
      "--threat-model", threatModelPath,
      "--focus-areas", focusAreasPath,
      "--focus-area", "FA-001",
      "--output", join(coverage, "invalid-ai-skeleton.audit-report.json"),
    ], 1);
    const aiSkeletonPath = join(coverage, "ai-skeleton.audit-report.json");
    run("initialize-audit-report.mjs", [
      "--audit-id", AUDIT_ID,
      "--round", "1",
      "--agent", "ai-security-auditor",
      "--session", "ai-config-r1",
      "--lens", "config-driven",
      "--language", "ai",
      "--scope", scopePath,
      "--functions", javaPath,
      "--functions", jsPath,
      "--functions", embeddedPath,
      "--catalog", CATALOG,
      "--threat-model", threatModelPath,
      "--focus-areas", focusAreasPath,
      "--focus-area", "FA-001",
      "--ai-surfaces", aiSurfacesPath,
      "--output", aiSkeletonPath,
    ]);
    const aiSkeleton = JSON.parse(await readFile(aiSkeletonPath, "utf8"));
    const aiCatalogCount = catalog.entries.filter(entry => entry.applies_to.includes("ai")).length;
    if (aiSkeleton.file_coverage.length !== scope.files.filter(file => file.review_required).length
      || aiSkeleton.function_coverage.length !== manifests.flatMap(manifest => manifest.functions).length
      || aiSkeleton.catalog_coverage.length !== aiCatalogCount
      || [...aiSkeleton.file_coverage, ...aiSkeleton.function_coverage, ...aiSkeleton.catalog_coverage].some(record => record.domain !== "ai" || record.status !== "GAP")
      || !aiSkeleton.tool_inputs.some(input => input.kind === "ai-surfaces" && input.scope_digest === scope.scope_digest)) {
      throw new Error("Report initializer did not create the exact full-scope AI overlay matrix");
    }
    const oneWebFunction = manifests.flatMap(manifest => manifest.functions).find(fn => fn.owner_agent === "web-source-auditor");
    const subsetAssignmentPath = join(coverage, "follow-up-assignment.json");
    await writeFile(subsetAssignmentPath, `${JSON.stringify({ file_ids: [], function_ids: [oneWebFunction.function_id], catalog_ids: [] }, null, 2)}\n`, "utf8");
    const subsetSkeletonPath = join(coverage, "web-subset-skeleton.audit-report.json");
    run("initialize-audit-report.mjs", [
      "--audit-id", AUDIT_ID,
      "--round", "2",
      "--agent", "web-source-auditor",
      "--session", "web-control-r2",
      "--lens", "control-driven",
      "--language", "web",
      "--scope", scopePath,
      "--functions", javaPath,
      "--functions", jsPath,
      "--functions", embeddedPath,
      "--catalog", CATALOG,
      "--threat-model", threatModelPath,
      "--focus-areas", focusAreasPath,
      "--focus-area", "FA-001",
      "--assignment", subsetAssignmentPath,
      "--output", subsetSkeletonPath,
    ]);
    const subsetSkeleton = JSON.parse(await readFile(subsetSkeletonPath, "utf8"));
    if (subsetSkeleton.file_coverage.length !== 0 || subsetSkeleton.function_coverage.length !== 1 || subsetSkeleton.catalog_coverage.length !== 0
      || subsetSkeleton.function_coverage[0].function_id !== oneWebFunction.function_id) {
      throw new Error("Follow-up assignment did not initialize the exact requested subset");
    }
    await makeReports(positiveReports, scope, manifests, catalog);

    const snapshotDir = join(work, "durable-snapshot");
    run("snapshot-coverage-inputs.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      "--functions", javaPath,
      "--functions", jsPath,
      "--functions", embeddedPath,
      "--interfaces", interfacesPath,
      "--interface-extractors", interfaceExtractorsPath,
      "--catalog", CATALOG,
      "--threat-model", threatModelPath,
      "--focus-areas", focusAreasPath,
      "--output-dir", snapshotDir,
    ]);
    const snapshotIndexPath = join(snapshotDir, "snapshot-index.json");
    const snapshotIndex = JSON.parse(await readFile(snapshotIndexPath, "utf8"));
    const snapshotScopePath = snapshotIndex.scope.path;
    const snapshotCatalogPath = snapshotIndex.catalog.path;
    const snapshotInterfacesPath = snapshotIndex.interfaces.path;
    const snapshotInterfaceExtractorsPath = snapshotIndex.interface_extractors.path;
    const snapshotFunctionPaths = snapshotIndex.functions.map(item => item.path);

    const commonVerifyArgs = [
      "--root", root,
      "--audit-id", AUDIT_ID,
      "--scope", snapshotScopePath,
      "--interfaces", snapshotInterfacesPath,
      "--interface-extractors", snapshotInterfaceExtractorsPath,
      "--snapshot-index", snapshotIndexPath,
      ...snapshotFunctionPaths.flatMap(path => ["--functions", path]),
      "--catalog", snapshotCatalogPath,
    ];
    const positiveOutput = join(coverage, "verification-positive.json");
    run("verify-coverage.mjs", [...commonVerifyArgs, "--reports-dir", positiveReports, "--output", positiveOutput]);
    const positive = JSON.parse(await readFile(positiveOutput, "utf8"));
    if (!positive.complete) throw new Error("Positive coverage fixture did not verify as complete");
    if (positive.expected.external_interfaces !== interfaceManifest.interfaces.length
      || positive.interface_extractor_verification?.complete !== true) {
      throw new Error("Coverage verification did not preserve the exact external-interface universe");
    }

    const coveragePlanPath = join(coverage, "coverage-plan.json");
    run("build-coverage-plan.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", snapshotScopePath,
      ...snapshotFunctionPaths.flatMap(path => ["--functions", path]),
      "--interfaces", snapshotInterfacesPath,
      "--interface-extractors", snapshotInterfaceExtractorsPath,
      "--catalog", snapshotCatalogPath,
      "--focus-areas", snapshotIndex.semantic.focus_areas.path,
      "--output", coveragePlanPath,
    ]);
    const coveragePlan = JSON.parse(await readFile(coveragePlanPath, "utf8"));
    if (!coveragePlan.complete || coveragePlan.summary.required === 0
      || coveragePlan.summary.catalog_domain_required === 0 || coveragePlan.summary.interface_required === 0
      || validatePlan(coveragePlan).length > 0) {
      throw new Error("Coverage Plan v2 did not produce a complete sparse catalog/interface check universe");
    }
    const negativeLensPlan = structuredClone(coveragePlan);
    const removedLensCheck = negativeLensPlan.checks.shift();
    negativeLensPlan.summary.atomic_checks = negativeLensPlan.checks.length;
    negativeLensPlan.summary.required = negativeLensPlan.checks.filter(check => check.applicability === "REQUIRED").length;
    negativeLensPlan.summary.not_applicable = negativeLensPlan.checks.filter(check => check.applicability === "NOT_APPLICABLE").length;
    negativeLensPlan.summary.unknown = negativeLensPlan.checks.filter(check => check.applicability === "UNKNOWN").length;
    negativeLensPlan.summary.catalog_domain_required = negativeLensPlan.checks.filter(check => check.subject_kind === "catalog-domain" && check.applicability === "REQUIRED").length;
    negativeLensPlan.summary.interface_required = negativeLensPlan.checks.filter(check => check.subject_kind === "interface" && check.applicability === "REQUIRED").length;
    negativeLensPlan.manifest_digest = objectDigest(negativeLensPlan);
    if (!validatePlan(negativeLensPlan).some(error => error.includes("tri-lens group incomplete"))) {
      throw new Error(`Coverage Plan accepted a two-lens group after removing ${removedLensCheck.check_id}`);
    }

    const ledgerPath = join(coverage, "coverage-ledger.jsonl");
    await initializeLedger({ planPath: coveragePlanPath, ledgerPath });
    const firstRequiredCheck = coveragePlan.checks.find(check => check.applicability === "REQUIRED");
    const frozenSource = coveragePlan.source_index.find(source => typeof source.sha256 === "string");
    await expectReject(() => inspectSubject({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: "check:forged",
      sessionId: "fixture-ledger-session",
      idempotencyKey: "fake-check",
    }), /Unknown coverage check_id/);
    await expectReject(() => recordToolResult({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-ledger-session",
      idempotencyKey: "stale-receipt",
      sourceHashes: [{ file_id: frozenSource.file_id, sha256: "0".repeat(64) }],
      locators: [{ path: frozenSource.path, line_start: 1 }],
      queryOrRule: "fixture-negative-search",
      tool: "fixture",
      resultDigest: sha256("fixture-stale"),
      resultSummary: "stale",
    }), /Stale or non-frozen source hash/);
    await expectReject(() => submitDecision({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-ledger-session",
      idempotencyKey: "missing-receipt",
      executionState: "VERIFIED",
      resultState: "NO_FINDING",
      receiptIds: [],
      rationale: "invalid no-evidence decision",
    }), /requires at least one receipt/);
    await expectReject(() => submitDecision({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-ledger-session",
      idempotencyKey: "agent-na",
      executionState: "N/A",
      resultState: "INCONCLUSIVE",
      rationale: "invalid agent N/A",
    }), /N\/A is planner-only/);
    const multiSourceCheck = coveragePlan.checks.find(check => check.applicability === "REQUIRED" && check.required_source_file_ids.length > 1);
    const partialSource = coveragePlan.source_index.find(source => source.file_id === multiSourceCheck.required_source_file_ids[0]);
    const partialReceipt = await recordToolResult({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: multiSourceCheck.check_id,
      sessionId: "fixture-ledger-session",
      idempotencyKey: "partial-source-receipt",
      sourceHashes: [{ file_id: partialSource.file_id, sha256: partialSource.sha256, link_target: partialSource.link_target }],
      locators: [{ path: partialSource.path, line_start: 1 }],
      queryOrRule: "fixture-incomplete-domain-search",
      tool: "fixture",
      resultDigest: sha256("fixture-partial-source"),
      resultSummary: "Incomplete source universe.",
    });
    await expectReject(() => submitDecision({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: multiSourceCheck.check_id,
      sessionId: "fixture-ledger-session",
      idempotencyKey: "partial-source-decision",
      executionState: "VERIFIED",
      resultState: "NO_FINDING",
      receiptIds: [partialReceipt.receipt.receipt_id],
      rationale: "invalid partial source decision",
    }), /do not cover the frozen source universe/);

    for (const check of coveragePlan.checks.filter(item => item.applicability === "REQUIRED")) {
      const requiredSources = check.required_source_file_ids.map(fileId => {
        const source = coveragePlan.source_index.find(item => item.file_id === fileId);
        return { file_id: source.file_id, sha256: source.sha256, link_target: source.link_target };
      });
      const receipt = await recordToolResult({
        planPath: coveragePlanPath,
        ledgerPath,
        checkId: check.check_id,
        sessionId: "fixture-ledger-session",
        idempotencyKey: `receipt-${check.check_id}`,
        sourceHashes: requiredSources,
        locators: requiredSources.map(source => ({
          file_id: source.file_id,
          path: coveragePlan.source_index.find(item => item.file_id === source.file_id).path,
          line_start: 1,
          check_id: check.check_id,
        })),
        queryOrRule: `fixture-review:${check.vulnerability_type_id}:${check.lens}`,
        tool: "fixture-deterministic-review",
        resultDigest: sha256(`result:${check.check_id}`),
        resultSummary: "No fixture finding.",
      });
      await submitDecision({
        planPath: coveragePlanPath,
        ledgerPath,
        checkId: check.check_id,
        sessionId: "fixture-ledger-session",
        idempotencyKey: `decision-${check.check_id}`,
        executionState: "VERIFIED",
        resultState: "NO_FINDING",
        receiptIds: [receipt.receipt.receipt_id],
        rationale: "Digest-bound fixture evidence reviewed.",
      });
    }
    await finalizeLedger({ planPath: coveragePlanPath, ledgerPath, idempotencyKey: "fixture-finalize" });
    const ledgerVerification = await verifyLedger({ planPath: coveragePlanPath, ledgerPath, requireFinalized: true });
    if (!ledgerVerification.complete || ledgerVerification.gaps.length > 0) throw new Error("Completed Coverage Ledger v2 did not verify");

    const v2Output = join(coverage, "coverage-verification-v2.json");
    run("verify-coverage-v2.mjs", [
      "--audit-id", AUDIT_ID,
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural", positiveOutput,
      "--output", v2Output,
    ]);
    const v2Verification = JSON.parse(await readFile(v2Output, "utf8"));
    if (!v2Verification.complete
      || v2Verification.summary.accounting.known_coverage.percentage !== 100
      || v2Verification.summary.external_interfaces.complete_interfaces.percentage !== 100) {
      throw new Error("Coverage v2 final gate did not derive complete ledger/interface statistics");
    }
    const summaryPath = join(coverage, "coverage-summary.json");
    run("render-coverage-summary.mjs", [
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural", positiveOutput,
      "--output", summaryPath,
    ]);
    run("verify-coverage-summary.mjs", [
      "--summary", summaryPath,
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural", positiveOutput,
    ]);
    const tamperedSummaryPath = join(coverage, "coverage-summary-tampered.json");
    const tamperedSummary = JSON.parse(await readFile(summaryPath, "utf8"));
    tamperedSummary.accounting.known_coverage.percentage = 99.99;
    tamperedSummary.manifest_digest = objectDigest(tamperedSummary);
    await writeFile(tamperedSummaryPath, `${JSON.stringify(tamperedSummary, null, 2)}\n`, "utf8");
    run("verify-coverage-summary.mjs", [
      "--summary", tamperedSummaryPath,
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural", positiveOutput,
    ], 1);

    const tamperedLedgerPath = join(coverage, "coverage-ledger-tampered.jsonl");
    const ledgerLines = (await readFile(ledgerPath, "utf8")).trim().split("\n").map(JSON.parse);
    const receiptEvent = ledgerLines.find(event => event.event_type === "RECEIPT");
    receiptEvent.result_summary = "tampered after sealing";
    await writeFile(tamperedLedgerPath, `${ledgerLines.map(JSON.stringify).join("\n")}\n`, "utf8");
    await expectReject(() => verifyLedger({
      planPath: coveragePlanPath,
      ledgerPath: tamperedLedgerPath,
      requireFinalized: true,
    }), /Ledger hash mismatch/);

    const mixedRoundReports = join(work, "reports-mixed-round");
    await cp(positiveReports, mixedRoundReports, { recursive: true });
    subsetSkeleton.function_coverage[0] = {
      ...subsetSkeleton.function_coverage[0],
      status: "REVIEWED",
      gap_reason: null,
      evidence: [{
        kind: "function-location",
        function_id: oneWebFunction.function_id,
        path: oneWebFunction.path,
        code_sha256: oneWebFunction.code_sha256,
        qualified_name: oneWebFunction.qualified_name,
        line_start: oneWebFunction.line_start,
      }],
    };
    const subsetReportPath = join(mixedRoundReports, "web-source-auditor.control-driven.r2.audit-report.json");
    await writeFile(subsetReportPath, `${JSON.stringify(subsetSkeleton, null, 2)}\n`, "utf8");
    run("reconcile-audit-report.mjs", ["--report", subsetReportPath, "--scope", scopePath, "--catalog", CATALOG]);
    const mixedRoundOutput = join(coverage, "verification-mixed-round.json");
    run("verify-coverage.mjs", [...commonVerifyArgs, "--reports-dir", mixedRoundReports, "--output", mixedRoundOutput]);
    const mixedRound = JSON.parse(await readFile(mixedRoundOutput, "utf8"));
    if (!mixedRound.complete) throw new Error("A valid targeted gap round incorrectly invalidated earlier completed records");

    await cp(positiveReports, negativeReports, { recursive: true });
    const negativeReportPath = join(negativeReports, "web-source-auditor.sink-driven.audit-report.json");
    const negativeReport = JSON.parse(await readFile(negativeReportPath, "utf8"));
    if (negativeReport.function_coverage.length === 0) throw new Error("Negative fixture has no web function to remove");
    const removedFunction = negativeReport.function_coverage.shift().function_id;
    await writeFile(negativeReportPath, `${JSON.stringify(negativeReport, null, 2)}\n`, "utf8");
    const negativeOutput = join(coverage, "verification-negative.json");
    run("verify-coverage.mjs", [...commonVerifyArgs, "--reports-dir", negativeReports, "--output", negativeOutput], 2);
    const negative = JSON.parse(await readFile(negativeOutput, "utf8"));
    const caught = negative.missing.functions.some(item => item.function_id === removedFunction && item.domain === "base" && item.lens === "sink-driven");
    if (negative.complete || !caught) throw new Error("Negative coverage fixture did not catch the removed function/lens cell");
    const negativeSummaryPath = join(coverage, "coverage-summary-missing-function.json");
    run("render-coverage-summary.mjs", [
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural", negativeOutput,
      "--output", negativeSummaryPath,
    ], 2);
    const negativeSummary = JSON.parse(await readFile(negativeSummaryPath, "utf8"));
    if (negativeSummary.complete || negativeSummary.functions.complete_entities.percentage >= 100
      || negativeSummary.files.complete_entities.percentage >= 100
      || negativeSummary.files.contained_function_gap_files === 0) {
      throw new Error("Machine summary did not propagate a missing function into function and containing-file completeness");
    }

    const aiNegativeReports = join(work, "reports-ai-negative");
    await cp(positiveReports, aiNegativeReports, { recursive: true });
    const aiNegativeReportPath = join(aiNegativeReports, "ai-security-auditor.config-driven.audit-report.json");
    const aiNegativeReport = JSON.parse(await readFile(aiNegativeReportPath, "utf8"));
    if (aiNegativeReport.file_coverage.length === 0) throw new Error("AI negative fixture has no overlay file to remove");
    const removedAiFile = aiNegativeReport.file_coverage.shift().file_id;
    await writeFile(aiNegativeReportPath, `${JSON.stringify(aiNegativeReport, null, 2)}\n`, "utf8");
    const aiNegativeOutput = join(coverage, "verification-ai-negative.json");
    run("verify-coverage.mjs", [...commonVerifyArgs, "--reports-dir", aiNegativeReports, "--output", aiNegativeOutput], 2);
    const aiNegative = JSON.parse(await readFile(aiNegativeOutput, "utf8"));
    const aiOverlayCaught = aiNegative.missing.files.some(item => item.file_id === removedAiFile && item.domain === "ai" && item.owner_agent === "ai-security-auditor" && item.lens === "config-driven");
    if (aiNegative.complete || !aiOverlayCaught) throw new Error("Negative coverage fixture did not catch the removed AI file overlay cell");

    const dimensionReports = join(work, "reports-dimension-negative");
    await cp(positiveReports, dimensionReports, { recursive: true });
    const dimensionReportPath = join(dimensionReports, "java-source-auditor.control-driven.audit-report.json");
    const dimensionReport = JSON.parse(await readFile(dimensionReportPath, "utf8"));
    dimensionReport.coverage_cells = dimensionReport.coverage_cells.filter(cell => cell.dimension !== "D10");
    await writeFile(dimensionReportPath, `${JSON.stringify(dimensionReport, null, 2)}\n`, "utf8");
    const dimensionOutput = join(coverage, "verification-dimension-negative.json");
    run("verify-coverage.mjs", [...commonVerifyArgs, "--reports-dir", dimensionReports, "--output", dimensionOutput], 2);
    const dimensionNegative = JSON.parse(await readFile(dimensionOutput, "utf8"));
    const dimensionCaught = dimensionNegative.issues.some(issue => issue.code === "INVALID_DIMENSION_COVERAGE" && issue.report === dimensionReportPath);
    if (dimensionNegative.complete || !dimensionCaught) throw new Error("Missing D1-D10 coverage cell did not block complete verification");

    const selfReportedReports = join(work, "reports-self-reported-count-negative");
    await cp(positiveReports, selfReportedReports, { recursive: true });
    const selfReportedPath = join(selfReportedReports, "java-source-auditor.sink-driven.audit-report.json");
    const selfReported = JSON.parse(await readFile(selfReportedPath, "utf8"));
    selfReported.coverage_cells[0].targets_discovered = 999;
    selfReported.coverage_cells[0].targets_reviewed = 999;
    await writeFile(selfReportedPath, `${JSON.stringify(selfReported, null, 2)}\n`, "utf8");
    const selfReportedOutput = join(coverage, "verification-self-reported-count.json");
    run("verify-coverage.mjs", [...commonVerifyArgs, "--reports-dir", selfReportedReports, "--output", selfReportedOutput], 2);
    const selfReportedVerification = JSON.parse(await readFile(selfReportedOutput, "utf8"));
    const selfReportedCaught = selfReportedVerification.issues.some(issue => issue.code === "INVALID_DIMENSION_COVERAGE"
      && issue.report === selfReportedPath && issue.errors.includes("D1:self-reported-target-count-forbidden"));
    if (selfReportedVerification.complete || !selfReportedCaught) throw new Error("Self-reported coverage-cell counts did not block complete verification");

    const forgedEvidenceReports = join(work, "reports-forged-evidence-negative");
    await cp(positiveReports, forgedEvidenceReports, { recursive: true });
    const forgedEvidencePath = join(forgedEvidenceReports, "java-source-auditor.sink-driven.audit-report.json");
    const forgedEvidence = JSON.parse(await readFile(forgedEvidencePath, "utf8"));
    forgedEvidence.file_coverage[0].evidence[0].sha256 = "0".repeat(64);
    await writeFile(forgedEvidencePath, `${JSON.stringify(forgedEvidence, null, 2)}\n`, "utf8");
    const forgedEvidenceOutput = join(coverage, "verification-forged-evidence.json");
    run("verify-coverage.mjs", [...commonVerifyArgs, "--reports-dir", forgedEvidenceReports, "--output", forgedEvidenceOutput], 2);
    const forgedEvidenceVerification = JSON.parse(await readFile(forgedEvidenceOutput, "utf8"));
    const forgedEvidenceCaught = forgedEvidenceVerification.invalid.files.some(item => item.report === forgedEvidencePath
      && item.errors.includes("file-evidence-not-bound-to-frozen-source"));
    if (forgedEvidenceVerification.complete || !forgedEvidenceCaught) throw new Error("Forged source evidence did not block complete verification");

    const selfDeclaredNaReports = join(work, "reports-self-declared-na-negative");
    await cp(positiveReports, selfDeclaredNaReports, { recursive: true });
    const selfDeclaredNaPath = join(selfDeclaredNaReports, "java-source-auditor.sink-driven.audit-report.json");
    const selfDeclaredNa = JSON.parse(await readFile(selfDeclaredNaPath, "utf8"));
    selfDeclaredNa.function_coverage[0].status = "N/A";
    selfDeclaredNa.function_coverage[0].na_reason = "agent-declared-not-applicable";
    await writeFile(selfDeclaredNaPath, `${JSON.stringify(selfDeclaredNa, null, 2)}\n`, "utf8");
    const selfDeclaredNaOutput = join(coverage, "verification-self-declared-na.json");
    run("verify-coverage.mjs", [...commonVerifyArgs, "--reports-dir", selfDeclaredNaReports, "--output", selfDeclaredNaOutput], 2);
    const selfDeclaredNaVerification = JSON.parse(await readFile(selfDeclaredNaOutput, "utf8"));
    const selfDeclaredNaCaught = selfDeclaredNaVerification.invalid.functions.some(item => item.report === selfDeclaredNaPath
      && item.errors.includes("invalid-status"));
    if (selfDeclaredNaVerification.complete || !selfDeclaredNaCaught) throw new Error("Agent-declared N/A record did not block complete verification");

    const tamperedScopePath = join(coverage, "scope-tampered.json");
    const tamperedScope = JSON.parse(await readFile(scopePath, "utf8"));
    const tamperedFile = tamperedScope.files.find(file => file.owner_agent !== "platform-security-auditor");
    if (!tamperedFile) throw new Error("Coverage fixture has no non-platform file for policy tampering");
    tamperedFile.owner_agent = "platform-security-auditor";
    await writeFile(tamperedScopePath, `${JSON.stringify(tamperedScope, null, 2)}\n`, "utf8");
    const tamperedScopeOutput = join(coverage, "verification-scope-tampered.json");
    run("verify-coverage.mjs", [
      "--root", root,
      "--audit-id", AUDIT_ID,
      "--scope", tamperedScopePath,
      "--interfaces", snapshotInterfacesPath,
      "--interface-extractors", snapshotInterfaceExtractorsPath,
      "--snapshot-index", snapshotIndexPath,
      ...snapshotFunctionPaths.flatMap(path => ["--functions", path]),
      "--reports-dir", positiveReports,
      "--catalog", snapshotCatalogPath,
      "--output", tamperedScopeOutput,
    ], 2);
    const tamperedScopeVerification = JSON.parse(await readFile(tamperedScopeOutput, "utf8"));
    if (!tamperedScopeVerification.issues.some(issue => issue.code === "SCOPE_MANIFEST_DIGEST_INVALID")
      || !tamperedScopeVerification.issues.some(issue => issue.code === "SCOPE_POLICY_DRIFT")) {
      throw new Error("Tampered scope owner/parser policy was not detected");
    }

    const snapshotJavaPath = snapshotIndex.functions.find(item => item.language === "java").path;
    const tamperedFunctionsPath = join(coverage, "functions-java-tampered.json");
    const tamperedFunctions = JSON.parse(await readFile(snapshotJavaPath, "utf8"));
    tamperedFunctions.functions.shift();
    await writeFile(tamperedFunctionsPath, `${JSON.stringify(tamperedFunctions, null, 2)}\n`, "utf8");
    const tamperedFunctionsOutput = join(coverage, "verification-functions-tampered.json");
    run("verify-coverage.mjs", [
      "--root", root,
      "--audit-id", AUDIT_ID,
      "--scope", snapshotScopePath,
      "--interfaces", snapshotInterfacesPath,
      "--interface-extractors", snapshotInterfaceExtractorsPath,
      "--snapshot-index", snapshotIndexPath,
      "--functions", tamperedFunctionsPath,
      ...snapshotFunctionPaths.filter(path => path !== snapshotJavaPath).flatMap(path => ["--functions", path]),
      "--reports-dir", positiveReports,
      "--catalog", snapshotCatalogPath,
      "--output", tamperedFunctionsOutput,
    ], 2);
    const tamperedFunctionsVerification = JSON.parse(await readFile(tamperedFunctionsOutput, "utf8"));
    if (!tamperedFunctionsVerification.issues.some(issue => issue.code === "FUNCTION_MANIFEST_DIGEST_INVALID")) {
      throw new Error("Tampered function manifest was not detected");
    }

    const tamperedInterfacesPath = join(coverage, "interface-manifest-tampered.json");
    const tamperedInterfaces = JSON.parse(await readFile(snapshotInterfacesPath, "utf8"));
    tamperedInterfaces.interfaces[0].address = "/forged-interface";
    await writeFile(tamperedInterfacesPath, `${JSON.stringify(tamperedInterfaces, null, 2)}\n`, "utf8");
    const tamperedInterfacesOutput = join(coverage, "verification-interfaces-tampered.json");
    run("verify-coverage.mjs", [
      "--root", root,
      "--audit-id", AUDIT_ID,
      "--scope", snapshotScopePath,
      "--interfaces", tamperedInterfacesPath,
      "--interface-extractors", snapshotInterfaceExtractorsPath,
      "--snapshot-index", snapshotIndexPath,
      ...snapshotFunctionPaths.flatMap(path => ["--functions", path]),
      "--reports-dir", positiveReports,
      "--catalog", snapshotCatalogPath,
      "--output", tamperedInterfacesOutput,
    ], 2);
    const tamperedInterfacesVerification = JSON.parse(await readFile(tamperedInterfacesOutput, "utf8"));
    if (!tamperedInterfacesVerification.issues.some(issue => issue.code === "SNAPSHOT_INTERFACE_HASH_MISMATCH")
      || !tamperedInterfacesVerification.issues.some(issue => issue.code === "INTERFACE_MANIFEST_INVALID")) {
      throw new Error("Tampered interface manifest was not rejected by snapshot and content binding");
    }

    const dynamicInterfaceRoot = join(work, "fixture-dynamic-interface");
    const dynamicInterfaceCoverage = join(work, "coverage-dynamic-interface");
    await cp(FIXTURE, dynamicInterfaceRoot, { recursive: true });
    await writeFile(join(dynamicInterfaceRoot, "static", "dynamic-route.js"), "const dynamicPath = process.env.ROUTE;\napp.get(dynamicPath, handler);\n", "utf8");
    await mkdir(dynamicInterfaceCoverage, { recursive: true });
    const dynamicScopePath = join(dynamicInterfaceCoverage, "scope.json");
    const dynamicInterfacesPath = join(dynamicInterfaceCoverage, "interface-manifest.json");
    const dynamicExtractorsPath = join(dynamicInterfaceCoverage, "interface-extractor-coverage.json");
    run("build-scope-manifest.mjs", ["--root", dynamicInterfaceRoot, "--audit-id", AUDIT_ID, "--output", dynamicScopePath]);
    run("build-interface-manifest.mjs", ["--root", dynamicInterfaceRoot, "--audit-id", AUDIT_ID, "--scope", dynamicScopePath, "--output", dynamicInterfacesPath]);
    run("verify-interface-extractors.mjs", ["--audit-id", AUDIT_ID, "--scope", dynamicScopePath, "--interfaces", dynamicInterfacesPath, "--output", dynamicExtractorsPath], 2);
    const dynamicExtractorVerification = JSON.parse(await readFile(dynamicExtractorsPath, "utf8"));
    if (dynamicExtractorVerification.complete
      || !dynamicExtractorVerification.issues.some(issue => issue.code === "INTERFACE_EXTRACTION_GAP" && issue.path === "static/dynamic-route.js")) {
      throw new Error("Dynamic interface registration did not block complete interface inventory");
    }

    const failedExtractorRoot = join(work, "fixture-failed-interface-extractor");
    const failedExtractorCoverage = join(work, "coverage-failed-interface-extractor");
    await cp(FIXTURE, failedExtractorRoot, { recursive: true });
    await mkdir(failedExtractorCoverage, { recursive: true });
    const failedScopePath = join(failedExtractorCoverage, "scope.json");
    const failedInterfacesPath = join(failedExtractorCoverage, "interface-manifest.json");
    const failedExtractorsPath = join(failedExtractorCoverage, "interface-extractor-coverage.json");
    run("build-scope-manifest.mjs", ["--root", failedExtractorRoot, "--audit-id", AUDIT_ID, "--output", failedScopePath]);
    await writeFile(join(failedExtractorRoot, "static", "app.js"), "source changed after the scope was frozen\n", "utf8");
    run("build-interface-manifest.mjs", ["--root", failedExtractorRoot, "--audit-id", AUDIT_ID, "--scope", failedScopePath, "--output", failedInterfacesPath]);
    run("verify-interface-extractors.mjs", ["--audit-id", AUDIT_ID, "--scope", failedScopePath, "--interfaces", failedInterfacesPath, "--output", failedExtractorsPath], 2);
    const failedExtractorVerification = JSON.parse(await readFile(failedExtractorsPath, "utf8"));
    if (failedExtractorVerification.complete
      || !failedExtractorVerification.issues.some(issue => issue.code === "INTERFACE_EXTRACTION_GAP" && issue.state === "FAILED")) {
      throw new Error("Failed interface source hashing did not block complete interface inventory");
    }

    const unsupportedRoot = join(work, "fixture-unsupported");
    const unsupportedCoverage = join(work, "coverage-unsupported");
    const unsupportedReports = join(work, "reports-unsupported");
    await cp(FIXTURE, unsupportedRoot, { recursive: true });
    await writeFile(join(unsupportedRoot, "Unsupported.groovy"), "def dynamicTask() { return 1 }\n", "utf8");
    await mkdir(unsupportedCoverage, { recursive: true });
    const unsupportedScopePath = join(unsupportedCoverage, "scope.json");
    const unsupportedJavaPath = join(unsupportedCoverage, "functions-java.json");
    const unsupportedJsPath = join(unsupportedCoverage, "functions-javascript.json");
    const unsupportedEmbeddedPath = join(unsupportedCoverage, "functions-embedded-web.json");
    const unsupportedInterfacesPath = join(unsupportedCoverage, "interface-manifest.json");
    const unsupportedInterfaceExtractorsPath = join(unsupportedCoverage, "interface-extractor-coverage.json");
    run("build-scope-manifest.mjs", ["--root", unsupportedRoot, "--audit-id", AUDIT_ID, "--output", unsupportedScopePath]);
    run("build-function-manifests.mjs", ["--root", unsupportedRoot, "--audit-id", AUDIT_ID, "--scope", unsupportedScopePath, "--output-dir", unsupportedCoverage, "--jobs", "2"]);
    const unsupportedScope = JSON.parse(await readFile(unsupportedScopePath, "utf8"));
    const unsupportedManifests = await Promise.all([unsupportedJavaPath, unsupportedJsPath, unsupportedEmbeddedPath].map(async path => JSON.parse(await readFile(path, "utf8"))));
    run("build-interface-manifest.mjs", ["--root", unsupportedRoot, "--audit-id", AUDIT_ID, "--scope", unsupportedScopePath, "--output", unsupportedInterfacesPath]);
    run("verify-interface-extractors.mjs", ["--audit-id", AUDIT_ID, "--scope", unsupportedScopePath, "--interfaces", unsupportedInterfacesPath, "--output", unsupportedInterfaceExtractorsPath], 2);
    await makeReports(unsupportedReports, unsupportedScope, unsupportedManifests, catalog);
    const unsupportedOutput = join(unsupportedCoverage, "verification.json");
    run("verify-coverage.mjs", [
      "--root", unsupportedRoot,
      "--audit-id", AUDIT_ID,
      "--scope", unsupportedScopePath,
      "--interfaces", unsupportedInterfacesPath,
      "--interface-extractors", unsupportedInterfaceExtractorsPath,
      "--snapshot-index", join(unsupportedCoverage, "missing-snapshot-index.json"),
      "--functions", unsupportedJavaPath,
      "--functions", unsupportedJsPath,
      "--functions", unsupportedEmbeddedPath,
      "--reports-dir", unsupportedReports,
      "--catalog", CATALOG,
      "--output", unsupportedOutput,
    ], 2);
    const unsupported = JSON.parse(await readFile(unsupportedOutput, "utf8"));
    const unsupportedCaught = unsupported.issues.some(issue => issue.code === "UNSUPPORTED_FUNCTION_INVENTORY" && issue.path === "Unsupported.groovy");
    if (unsupported.complete || !unsupportedCaught) throw new Error("Unsupported function-bearing source did not block complete verification");

    const malformedRoot = join(work, "fixture-malformed-js");
    const malformedCoverage = join(work, "coverage-malformed-js");
    await cp(MALFORMED_JS_FIXTURE, malformedRoot, { recursive: true });
    await mkdir(malformedCoverage, { recursive: true });
    const malformedScopePath = join(malformedCoverage, "scope.json");
    const malformedFunctionsPath = join(malformedCoverage, "functions-javascript.json");
    run("build-scope-manifest.mjs", ["--root", malformedRoot, "--audit-id", AUDIT_ID, "--output", malformedScopePath]);
    run("build-joern-function-manifest.mjs", ["--root", malformedRoot, "--audit-id", AUDIT_ID, "--scope", malformedScopePath, "--language", "javascript", "--output", malformedFunctionsPath], 2);
    const malformedFunctions = JSON.parse(await readFile(malformedFunctionsPath, "utf8"));
    if (malformedFunctions.complete || !malformedFunctions.missing_files.includes("broken.js")) throw new Error("Malformed JavaScript did not produce an explicit parser gap");

    process.stdout.write(`${JSON.stringify({ complete: true, positive: positive.expected, coverage_v2: { required_checks: coveragePlan.summary.required, not_applicable_checks: coveragePlan.summary.not_applicable, focus_area_bound: true, finalized_hash_chain: true, exact_summary: true }, git_aware_scope_pruning: true, function_manifest_resume_cache: true, cache_rejects_scope_drift: true, compact_threat_routing_index: true, deterministic_interface_inventory: true, dynamic_interface_gap_caught: "static/dynamic-route.js", failed_interface_extractor_caught: true, tampered_interface_manifest_caught: true, machine_reconciled_coverage_cells: true, self_reported_target_counts_rejected: true, forged_evidence_rejected: true, stale_receipt_rejected: true, incomplete_source_universe_rejected: true, receiptless_verified_rejected: true, fake_check_id_rejected: true, two_lens_plan_rejected: true, agent_declared_na_rejected: true, tampered_summary_rejected: true, tampered_ledger_chain_rejected: true, ai_initializer_requires_surface_inventory: true, targeted_gap_round_preserved_prior_coverage: true, negative_missing_function_caught: removedFunction, containing_file_completeness_reduced: true, negative_missing_ai_overlay_file_caught: removedAiFile, missing_dimension_cell_caught: "D10", tampered_scope_caught: true, tampered_function_manifest_caught: true, unsupported_function_source_caught: "Unsupported.groovy", malformed_javascript_caught: "broken.js" })}\n`);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
