#!/usr/bin/env node

import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPOSITORY = resolve(HERE, "../..");
const SCRIPTS = resolve(REPOSITORY, ".opencode/skills/common-subagent/audit-coverage-accounting/scripts");
const CATALOG = resolve(REPOSITORY, ".opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json");
const FIXTURE = resolve(HERE, "coverage-fixture");
const MALFORMED_JS_FIXTURE = resolve(HERE, "malformed-js-fixture");
const AUDIT_ID = "coverage-fixture-audit";
const LENSES = ["sink-driven", "control-driven", "config-driven"];
const DIMENSIONS = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);
const DOMAIN_AGENT = { java: "java-source-auditor", web: "web-source-auditor", ai: "ai-security-auditor" };

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
        coverage_cells: DIMENSIONS.map(dimension => ({
          dimension,
          lens,
          status: "PASS",
          targets_discovered: 1,
          targets_reviewed: 1,
          evidence: [{ fixture_check: `${agent}:${dimension}:${lens}` }],
          finding_ids: [],
          gap_reason: null,
          na_reason: null,
        })),
        file_coverage: assignedFiles
          .map(file => ({ file_id: file.file_id, domain: isAiOverlay ? "ai" : "base", status: "REVIEWED", dimensions_reviewed: DIMENSIONS, evidence: [{ path: file.path, sha256: file.sha256 }] })),
        function_coverage: assignedFunctions
          .map(fn => ({ function_id: fn.function_id, domain: isAiOverlay ? "ai" : "base", status: "REVIEWED", dimensions_reviewed: DIMENSIONS, evidence: [{ path: fn.path, qualified_name: fn.qualified_name }] })),
        catalog_coverage: catalog.entries
          .filter(entry => entry.applies_to.includes(domain))
          .map(entry => ({ catalog_id: entry.id, domain, status: "REVIEWED", dimensions_reviewed: entry.dimensions, evidence: [{ fixture_check: `${entry.id}:${domain}:${lens}` }] })),
        findings: [],
        artifacts: [],
        learning_candidates: [],
      };
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
    const routingIndexPath = join(coverage, "threat-routing-index.json");
    run("build-threat-routing-index.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      "--functions", javaPath,
      "--functions", jsPath,
      "--functions", embeddedPath,
      "--catalog", CATALOG,
      "--output", routingIndexPath,
    ]);
    const routingIndex = JSON.parse(await readFile(routingIndexPath, "utf8"));
    if (routingIndex.summary.files !== scope.files.length
      || routingIndex.summary.functions !== manifests.flatMap(manifest => manifest.functions).length
      || routingIndex.summary.catalog_entries !== catalog.entries.length) {
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
      "--catalog", CATALOG,
      "--threat-model", threatModelPath,
      "--focus-areas", focusAreasPath,
      "--output-dir", snapshotDir,
    ]);
    const snapshotIndexPath = join(snapshotDir, "snapshot-index.json");
    const snapshotIndex = JSON.parse(await readFile(snapshotIndexPath, "utf8"));
    const snapshotScopePath = snapshotIndex.scope.path;
    const snapshotCatalogPath = snapshotIndex.catalog.path;
    const snapshotFunctionPaths = snapshotIndex.functions.map(item => item.path);

    const commonVerifyArgs = [
      "--root", root,
      "--audit-id", AUDIT_ID,
      "--scope", snapshotScopePath,
      "--snapshot-index", snapshotIndexPath,
      ...snapshotFunctionPaths.flatMap(path => ["--functions", path]),
      "--catalog", snapshotCatalogPath,
    ];
    const positiveOutput = join(coverage, "verification-positive.json");
    run("verify-coverage.mjs", [...commonVerifyArgs, "--reports-dir", positiveReports, "--output", positiveOutput]);
    const positive = JSON.parse(await readFile(positiveOutput, "utf8"));
    if (!positive.complete) throw new Error("Positive coverage fixture did not verify as complete");

    const mixedRoundReports = join(work, "reports-mixed-round");
    await cp(positiveReports, mixedRoundReports, { recursive: true });
    subsetSkeleton.coverage_cells = subsetSkeleton.coverage_cells.map(cell => ({
      ...cell,
      status: "PASS",
      targets_discovered: 1,
      targets_reviewed: 1,
      gap_reason: null,
      evidence: [{ fixture_check: `round-2:${cell.dimension}` }],
    }));
    subsetSkeleton.function_coverage[0] = {
      ...subsetSkeleton.function_coverage[0],
      status: "REVIEWED",
      gap_reason: null,
      evidence: [{ fixture_check: "targeted-round-2-function-review" }],
    };
    await writeFile(join(mixedRoundReports, "web-source-auditor.control-driven.r2.audit-report.json"), `${JSON.stringify(subsetSkeleton, null, 2)}\n`, "utf8");
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

    const tamperedScopePath = join(coverage, "scope-tampered.json");
    const tamperedScope = JSON.parse(await readFile(scopePath, "utf8"));
    tamperedScope.files[0].owner_agent = "platform-security-auditor";
    await writeFile(tamperedScopePath, `${JSON.stringify(tamperedScope, null, 2)}\n`, "utf8");
    const tamperedScopeOutput = join(coverage, "verification-scope-tampered.json");
    run("verify-coverage.mjs", [
      "--root", root,
      "--audit-id", AUDIT_ID,
      "--scope", tamperedScopePath,
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
    run("build-scope-manifest.mjs", ["--root", unsupportedRoot, "--audit-id", AUDIT_ID, "--output", unsupportedScopePath]);
    run("build-function-manifests.mjs", ["--root", unsupportedRoot, "--audit-id", AUDIT_ID, "--scope", unsupportedScopePath, "--output-dir", unsupportedCoverage, "--jobs", "2"]);
    const unsupportedScope = JSON.parse(await readFile(unsupportedScopePath, "utf8"));
    const unsupportedManifests = await Promise.all([unsupportedJavaPath, unsupportedJsPath, unsupportedEmbeddedPath].map(async path => JSON.parse(await readFile(path, "utf8"))));
    await makeReports(unsupportedReports, unsupportedScope, unsupportedManifests, catalog);
    const unsupportedOutput = join(unsupportedCoverage, "verification.json");
    run("verify-coverage.mjs", [
      "--root", unsupportedRoot,
      "--audit-id", AUDIT_ID,
      "--scope", unsupportedScopePath,
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

    process.stdout.write(`${JSON.stringify({ complete: true, positive: positive.expected, git_aware_scope_pruning: true, function_manifest_resume_cache: true, cache_rejects_scope_drift: true, compact_threat_routing_index: true, ai_initializer_requires_surface_inventory: true, targeted_gap_round_preserved_prior_coverage: true, negative_missing_function_caught: removedFunction, negative_missing_ai_overlay_file_caught: removedAiFile, missing_dimension_cell_caught: "D10", tampered_scope_caught: true, tampered_function_manifest_caught: true, unsupported_function_source_caught: "Unsupported.groovy", malformed_javascript_caught: "broken.js" })}\n`);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
