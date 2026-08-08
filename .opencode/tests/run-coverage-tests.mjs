#!/usr/bin/env node

import { chmod, cp, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { catalogQuestionDigest, deriveCoverageCells } from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-cell-accounting.mjs";
import {
  beginCoverageUnit,
  checkpointLedger,
  delegateAssignment,
  finalizePartialLedger,
  finalizeLedger,
  initializeLedger,
  inspectSubject,
  recordToolResult,
  submitCoverageUnitAttestation,
  submitDecision,
  verifyLedger,
} from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-ledger-core.mjs";
import {
  DOMAIN_AGENTS,
  entryAppliesToDomain,
  objectDigest,
  sha256,
  sourceFileIdsForCheck,
  validatePlan,
} from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-v2-common.mjs";
import { candidateManifestDigest } from "../skills/common-subagent/finding-adjudication/scripts/finding-adjudication-contract.mjs";
import { buildCvssAssessmentManifest } from "../skills/common-subagent/finding-adjudication/scripts/cvss-assessment-contract.mjs";
import { attackChainManifestDigest } from "../skills/attack-chain-subagent/system-attack-chain-hunting/scripts/attack-chain-contract.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPOSITORY = resolve(HERE, "../..");
const SCRIPTS = resolve(REPOSITORY, ".opencode/skills/common-subagent/audit-coverage-accounting/scripts");
const ADJUDICATION_SCRIPTS = resolve(REPOSITORY, ".opencode/skills/common-subagent/finding-adjudication/scripts");
const CATALOG = resolve(REPOSITORY, ".opencode/shared/security-audit/catalogs/application-ai-vulnerability-catalog.json");
const FIXTURE = resolve(HERE, "coverage-fixture");
const MALFORMED_JS_FIXTURE = resolve(HERE, "malformed-js-fixture");
const AUDIT_ID = "coverage-fixture-audit";
const LENSES = ["sink-driven", "control-driven", "config-driven"];
const DIMENSIONS = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);
const DOMAIN_AGENT = DOMAIN_AGENTS;

async function writeParserCapabilities(path, scope, capabilities) {
  const manifest = {
    schema_version: 1,
    audit_id: AUDIT_ID,
    scope_digest: scope.scope_digest,
    capabilities,
    complete: capabilities.every(item => item.status === "available"),
  };
  manifest.manifest_digest = objectDigest(manifest);
  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

async function writeSyntheticFunctionManifest(path, scope, { language, ownerAgent, sourcePath, qualifiedName }) {
  const source = scope.files.find(file => file.path === sourcePath);
  if (!source) throw new Error(`Synthetic function source is outside scope: ${sourcePath}`);
  const fn = {
    function_id: `function:${sha256(`${language}|${sourcePath}|${qualifiedName}|1`).slice(0, 32)}`,
    language,
    owner_agent: ownerAgent,
    required_lenses: LENSES,
    code_sha256: source.sha256,
    path: sourcePath,
    kind: "function",
    qualified_name: qualifiedName,
    signature: `${qualifiedName}(...)`,
    line_start: 1,
    line_end: 3,
  };
  const manifest = {
    schema_version: 1,
    audit_id: AUDIT_ID,
    language,
    extractor: { name: "fixture-contract-extractor", frontend_language: language, input_mode: "test-fixture" },
    scope_manifest: null,
    scope_digest: scope.scope_digest,
    expected_files: [sourcePath],
    parsed_files: [sourcePath],
    missing_files: [],
    unexpected_cpg_files: [],
    functions: [fn],
    summary: { expected_files: 1, parsed_files: 1, functions: 1, missing_files: 0, unexpected_cpg_files: 0 },
    complete: true,
  };
  manifest.manifest_digest = objectDigest(manifest);
  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

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
    security_invariants: [{
      invariant_id: "INV-001",
      statement: "Untrusted fixture input must not control the fixture security operation.",
      asset_ids: ["ASSET-001"],
      threat_ids: ["T-001"],
      enforcement_points: ["fixture input validation"],
      evidence: [{ fixture: "invariant" }],
      provenance_tags: ["code-verified"],
    }],
    assumptions: [{
      assumption_id: "ASM-001",
      statement: "The fixture route is representative of a deployed HTTP boundary.",
      category: "deployment",
      status: "UNVERIFIED",
      affects_threat_ids: ["T-001"],
      evidence: [],
      provenance_tags: ["deployment-unknown"],
    }],
    attacker_stories: [{
      story_id: "STORY-001",
      actor_id: "ACTOR-001",
      entry_point_id: "EP-001",
      threat_id: "T-001",
      affected_asset_ids: ["ASSET-001"],
      preconditions: ["The fixture route is deployed."],
      steps: ["Supply attacker-controlled fixture input.", "Reach the fixture security operation."],
      outcome: "The attacker influences the fixture security operation.",
      evidence: [{ fixture: "story" }],
      provenance_tags: ["code-verified"],
    }],
    out_of_scope_stories: [{
      story_id: "OOS-001",
      scenario: "Compromise of infrastructure outside the fixture repository.",
      reason: "External infrastructure is not included in the frozen fixture scope.",
      reconsider_when: ["Infrastructure manifests are added to the frozen scope."],
      evidence: [{ fixture: "scope" }],
      provenance_tags: ["deployment-unknown"],
    }],
    severity_calibration: {
      model: "contextual-four-level-v1",
      context_notes: ["This calibration orders threat-model review; CVSS is derived after adjudication."],
      evidence: [{ fixture: "severity" }],
      levels: [
        { severity: "CRITICAL", criteria: ["Complete fixture compromise across all targets."], examples: [{ scenario: "All fixture targets are compromised.", rationale: "Fleet-wide impact.", threat_ids: ["T-001"] }], not_applicable_reason: null },
        { severity: "HIGH", criteria: ["Direct compromise of the primary fixture integrity asset."], examples: [{ scenario: "The primary fixture operation is attacker-controlled.", rationale: "Direct integrity loss.", threat_ids: ["T-001"] }], not_applicable_reason: null },
        { severity: "MEDIUM", criteria: ["A constrained operation is influenced under additional preconditions."], examples: [{ scenario: "Only a noncritical fixture branch is influenced.", rationale: "Constrained impact.", threat_ids: ["T-001"] }], not_applicable_reason: null },
        { severity: "LOW", criteria: ["The observable effect is minor and difficult to reach."], examples: [{ scenario: "Only a diagnostic fixture message changes.", rationale: "Minimal impact.", threat_ids: ["T-001"] }], not_applicable_reason: null },
      ],
    },
    deprioritized: [],
    history_clusters: [],
    entry_point_coverage: [{ entry_point_id: "EP-001", status: "THREAT", threat_ids: ["T-001"], reason: null, evidence: [{ fixture: true }] }],
    open_questions: [],
    provenance: { target: "coverage-fixture", commit: "fixture", inputs: ["test"], owner: null },
  }, null, 2)}\n`, "utf8");
  run("seal-semantic-manifest.mjs", ["--input", threatModelPath]);
  const threatModel = JSON.parse(await readFile(threatModelPath, "utf8"));
  const functions = manifests.flatMap(manifest => manifest.functions);
  const activeDomainNames = Object.keys(DOMAIN_AGENT)
    .filter(domain => domain === "ai" || scope.files.some(file => file.review_required && file.owner_agent === DOMAIN_AGENT[domain]));
  const assignments = Object.entries(DOMAIN_AGENT).filter(([domain]) => activeDomainNames.includes(domain)).map(([domain, agent]) => {
    const isAi = domain === "ai";
    return {
      assignment_id: `FA-001-${domain}-${isAi ? "ai" : "base"}`,
      agent_name: agent,
      language: domain,
      file_function_domain: isAi ? "ai" : "base",
      catalog_domain: domain,
      file_ids: scope.files.filter(file => file.review_required && (isAi || file.owner_agent === agent)).map(file => file.file_id),
      function_ids: functions.filter(fn => isAi || fn.owner_agent === agent).map(fn => fn.function_id),
      catalog_ids: catalog.entries.filter(entry => entryAppliesToDomain(entry, domain, catalog)).map(entry => entry.id),
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

function runAdjudication(script, args, expectedStatus = 0) {
  const result = spawnSync(process.execPath, [resolve(ADJUDICATION_SCRIPTS, script), ...args], {
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

function ledgerFindingArtifact(findingId, check, plan) {
  const sourceDigest = sha256(`fixture-source:${check.check_id}`);
  return {
    finding_schema_version: 2,
    finding_id: findingId,
    audit_id: plan.audit_id,
    scope_digest: plan.scope_digest,
    state: "CANDIDATE",
    classification: {
      vulnerability_type_id: check.vulnerability_type_id,
      origin_lens: check.lens,
      discovery_track: "coverage",
      dimension_claims: [{
        dimension: check.dimensions[0],
        rationale: "Fixture finding explicitly claims only the check's first dimension.",
      }],
    },
    routing: {
      focus_area_id: check.focus_area_id,
      primary_check_id: check.check_id,
      domain: check.domain,
      threat_ids: ["T-001"],
    },
    locations: {
      primary: {
        file: "src/main/java/com/example/SampleController.java",
        line_start: 1,
        source_digest: sourceDigest,
      },
    },
    evidence: {
      facts: [
        {
          kind: "source",
          claim: "Fixture request parameter reaches the security boundary.",
          locator: { file: "src/main/java/com/example/SampleController.java", line_start: 1, source_digest: sourceDigest },
          method: "fixture",
          source_digest: sourceDigest,
          confidence: "high",
        },
        {
          kind: "sink",
          claim: "Fixture security-sensitive operation is reachable.",
          locator: { file: "src/main/java/com/example/SampleController.java", line_start: 2, source_digest: sourceDigest },
          method: "fixture",
          source_digest: sourceDigest,
          confidence: "high",
        },
      ],
    },
    reachability: { state: "static-reachable" },
    attacker_influence: { state: "direct" },
    attack_surface: {
      schema_version: 1,
      in_scope: { state: "YES", rationale: "The fixture source is in the frozen scope.", evidence_fact_indexes: [0] },
      exposure: { state: "PUBLIC", surface: "fixture HTTP request parameter", rationale: "The request parameter is externally supplied.", evidence_fact_indexes: [0] },
      vector: { state: "NETWORK", rationale: "The input is modeled as a network request parameter.", evidence_fact_indexes: [0] },
      auth_scope: { state: "UNAUTHENTICATED", rationale: "The fixture check does not require an established identity.", evidence_fact_indexes: [0] },
      preconditions: [{
        precondition_id: "PRE-001",
        description: "The fixture route is deployed.",
        feasibility: "UNPROVEN",
        evidence_fact_indexes: [],
      }],
      identities: {
        attacker: "remote fixture caller",
        victim: "fixture application",
        effective_principal: "unauthenticated request context",
        evidence_fact_indexes: [0],
      },
      boundary_crossing: {
        state: "PROVEN",
        from: "fixture request",
        to: "fixture security operation",
        rationale: "The source reaches the semantic operation.",
        evidence_fact_indexes: [0, 1],
      },
      impact: {
        types: ["INTEGRITY"],
        outcome: "The fixture security operation is influenced by request input.",
        evidence_fact_indexes: [0, 1],
      },
      target_reach: {
        state: "SINGLE_SERVICE",
        rationale: "The fixture establishes one service-local operation.",
        evidence_fact_indexes: [1],
      },
      controls: [],
      counterevidence: [],
      blindspots: ["The fixture has no runtime deployment evidence."],
      confidence: { level: "medium", rationale: "Static source and sink facts are present; deployment is unverified." },
    },
    guards: [],
    contradictions: [],
    uncertainty: { level: "medium", assumptions: ["Fixture has no runtime deployment."] },
    severity: { rationale: "Fixture only verifies ledger binding." },
    remediation: { summary: "Fix the fixture security condition." },
    provenance: { source_report_sha256: sha256(`fixture-report:${check.check_id}`) },
  };
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
        schema_version: 2,
        finding_schema_version: 2,
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
          assigned_catalog_ids: catalog.entries.filter(entry => entryAppliesToDomain(entry, domain, catalog)).map(entry => entry.id),
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
          .filter(entry => entryAppliesToDomain(entry, domain, catalog))
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
    await mkdir(join(root, "src", "main", "python"), { recursive: true });
    await mkdir(join(root, "src", "main", "c"), { recursive: true });
    await writeFile(join(root, "src", "main", "python", "sample.py"), "def normalize(value):\n    return value.strip()\n", "utf8");
    await writeFile(join(root, "src", "main", "c", "sample.c"), [
      "#include <stddef.h>",
      "",
      "size_t fixture_length(const char *value) {",
      "    size_t length = 0;",
      "    while (value[length] != '\\0') length += 1;",
      "    return length;",
      "}",
      "",
    ].join("\n"), "utf8");
    await symlink("static/app.js", join(root, "linked-app.js"));
    await mkdir(coverage, { recursive: true });

    const gitScopeRoot = join(work, "git-scope");
    await mkdir(join(gitScopeRoot, "src"), { recursive: true });
    await mkdir(join(gitScopeRoot, "node_modules", "dependency"), { recursive: true });
    await mkdir(join(gitScopeRoot, ".atlas"), { recursive: true });
    await writeFile(join(gitScopeRoot, ".gitignore"), "node_modules/\n", "utf8");
    await writeFile(join(gitScopeRoot, "src", "app.js"), "export const value = 1;\n", "utf8");
    await writeFile(join(gitScopeRoot, "node_modules", "dependency", "index.js"), "module.exports = 1;\n", "utf8");
    await writeFile(join(gitScopeRoot, ".atlas", "atlas.db"), "ephemeral local analysis cache\n", "utf8");
    runCommand("git", ["-C", gitScopeRoot, "init", "--quiet"]);
    runCommand("git", ["-C", gitScopeRoot, "add", ".gitignore", "src/app.js"]);
    const gitScopePath = join(work, "git-scope.json");
    run("build-scope-manifest.mjs", ["--root", gitScopeRoot, "--audit-id", AUDIT_ID, "--output", gitScopePath]);
    const gitScope = JSON.parse(await readFile(gitScopePath, "utf8"));
    if (gitScope.policy.enumeration !== "git-index-plus-untracked-nonignored"
      || gitScope.files.some(file => file.path.startsWith("node_modules/"))
      || !gitScope.exclusions.some(item => item.path === "node_modules" && item.reason === "gitignore-policy")
      || !gitScope.exclusions.some(item => item.path === ".atlas" && item.reason === "local-code-facts-cache")) {
      throw new Error("Git-aware scope did not prune dependency and local-analysis-cache content");
    }

    const shellInterfaceRoot = join(work, "shell-interface");
    await mkdir(shellInterfaceRoot, { recursive: true });
    await writeFile(join(shellInterfaceRoot, "deploy.sh"), "#!/usr/bin/env bash\ndocker run --publish 8080:8080 fixture-app\n", "utf8");
    const shellScopePath = join(work, "shell-interface-scope.json");
    const shellRawInterfacesPath = join(work, "shell-interface-raw.json");
    const shellDecisionsPath = join(work, "shell-interface-decisions.json");
    const shellInterfacesPath = join(work, "shell-interface-resolved.json");
    run("build-scope-manifest.mjs", ["--root", shellInterfaceRoot, "--audit-id", AUDIT_ID, "--output", shellScopePath]);
    const shellScope = JSON.parse(await readFile(shellScopePath, "utf8"));
    if (shellScope.files[0]?.function_inventory_state !== "not-applicable"
      || shellScope.files[0]?.content_kind !== "deployment-script") {
      throw new Error("Deployment scripts must remain file/interface review subjects without inventing a function parser requirement");
    }
    run("build-interface-manifest.mjs", ["--root", shellInterfaceRoot, "--audit-id", AUDIT_ID, "--scope", shellScopePath, "--output", shellRawInterfacesPath]);
    run("build-source-anchored-interface-decisions.mjs", ["--audit-id", AUDIT_ID, "--input", shellRawInterfacesPath, "--output", shellDecisionsPath]);
    run("resolve-interface-candidates.mjs", ["--audit-id", AUDIT_ID, "--input", shellRawInterfacesPath, "--decisions", shellDecisionsPath, "--output", shellInterfacesPath]);
    const shellInterfaces = JSON.parse(await readFile(shellInterfacesPath, "utf8"));
    if (!shellInterfaces.complete || !shellInterfaces.inventory_bounded
      || !shellInterfaces.interfaces.some(item => item.address === "8080:8080" && item.evidence.some(evidence => evidence.extractor_id === "shell-deployment-interface-anchors"))) {
      throw new Error("Shell deployment interface extraction did not produce a source-anchored bounded port mapping");
    }

    const scopePath = join(coverage, "scope.json");
    const javaPath = join(coverage, "functions-java.json");
    const jsPath = join(coverage, "functions-javascript.json");
    const embeddedPath = join(coverage, "functions-embedded-web.json");
    const pythonPath = join(coverage, "functions-python.json");
    const cPath = join(coverage, "functions-c.json");
    const functionPaths = [javaPath, jsPath, embeddedPath, pythonPath, cPath];
    const rawInterfacesPath = join(coverage, "interface-manifest.raw.json");
    const rawInterfaceExtractorsPath = join(coverage, "interface-extractor-coverage.raw.json");
    const interfacesPath = join(coverage, "interface-manifest.json");
    const interfaceExtractorsPath = join(coverage, "interface-extractor-coverage.json");
    run("build-scope-manifest.mjs", ["--root", root, "--audit-id", AUDIT_ID, "--output", scopePath]);
    const scope = JSON.parse(await readFile(scopePath, "utf8"));
    const parserCapabilitiesPath = join(coverage, "parser-capabilities.json");
    await writeParserCapabilities(parserCapabilitiesPath, scope, [
      { parser: "javac-java", status: "available", reason: null },
      { parser: "joern-js", status: "available", reason: null },
      { parser: "embedded-web", status: "available", reason: null },
      { parser: "joern-python", status: "unavailable", reason: "fixture uses a contract manifest to isolate selector behavior" },
      { parser: "joern-c", status: "unavailable", reason: "fixture uses a contract manifest to isolate selector behavior" },
    ]);
    const buildFunctionArgs = [
      "--root", root,
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      "--output-dir", coverage,
      "--jobs", "2",
      "--parser-capabilities", parserCapabilitiesPath,
      "--allow-partial", "true",
    ];
    run("build-function-manifests.mjs", buildFunctionArgs);
    await writeSyntheticFunctionManifest(pythonPath, scope, {
      language: "python",
      ownerAgent: "python-source-auditor",
      sourcePath: "src/main/python/sample.py",
      qualifiedName: "normalize",
    });
    await writeSyntheticFunctionManifest(cPath, scope, {
      language: "c",
      ownerAgent: "c-cpp-source-auditor",
      sourcePath: "src/main/c/sample.c",
      qualifiedName: "fixture_length",
    });
    const cachedBuild = JSON.parse(run("build-function-manifests.mjs", buildFunctionArgs).stdout);
    if (!cachedBuild.manifests.every(manifest => manifest.cached === true)) throw new Error("Digest-bound function manifests were not reused on resume");
    const cachedSourcePath = join(root, "static", "app.js");
    const cachedSource = await readFile(cachedSourcePath, "utf8");
    await writeFile(cachedSourcePath, `${cachedSource}\n// scope drift fixture\n`, "utf8");
    run("build-joern-function-manifest.mjs", ["--root", root, "--audit-id", AUDIT_ID, "--scope", scopePath, "--language", "javascript", "--output", jsPath], 1);
    await writeFile(cachedSourcePath, cachedSource, "utf8");

    const manifests = await Promise.all(functionPaths.map(async path => JSON.parse(await readFile(path, "utf8"))));
    const catalog = JSON.parse(await readFile(CATALOG, "utf8"));
    run("build-interface-manifest.mjs", ["--root", root, "--audit-id", AUDIT_ID, "--scope", scopePath, "--output", rawInterfacesPath]);
    const rawInterfaceManifest = JSON.parse(await readFile(rawInterfacesPath, "utf8"));
    run("verify-interface-extractors.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      "--interfaces", rawInterfacesPath,
      "--output", rawInterfaceExtractorsPath,
    ]);
    const rawInterfaceExtractors = JSON.parse(await readFile(rawInterfaceExtractorsPath, "utf8"));
    if (!rawInterfaceExtractors.complete || rawInterfaceExtractors.inventory_bounded
      || rawInterfaceExtractors.interfaces.candidate === 0) {
      throw new Error("Candidate interfaces were not separated from extractor completeness");
    }
    const interfaceDecisionsPath = join(coverage, "interface-decisions.json");
    run("build-source-anchored-interface-decisions.mjs", [
      "--audit-id", AUDIT_ID,
      "--input", rawInterfacesPath,
      "--output", interfaceDecisionsPath,
    ]);
    const interfaceDecisions = JSON.parse(await readFile(interfaceDecisionsPath, "utf8"));
    if (interfaceDecisions.decisions.length !== rawInterfaceManifest.interfaces.filter(item => item.discovery_state === "CANDIDATE").length
      || !interfaceDecisions.decisions.every(decision => decision.evidence[0]?.kind === "interface-source-anchor")) {
      throw new Error("Source-anchored interface resolver did not bind every literal candidate to frozen evidence");
    }
    run("resolve-interface-candidates.mjs", [
      "--audit-id", AUDIT_ID,
      "--input", rawInterfacesPath,
      "--decisions", interfaceDecisionsPath,
      "--output", interfacesPath,
    ]);
    run("verify-interface-extractors.mjs", ["--audit-id", AUDIT_ID, "--scope", scopePath, "--interfaces", interfacesPath, "--output", interfaceExtractorsPath]);
    const interfaceManifest = JSON.parse(await readFile(interfacesPath, "utf8"));
    const interfaceExtractorCoverage = JSON.parse(await readFile(interfaceExtractorsPath, "utf8"));
    if (!interfaceManifest.complete || !interfaceExtractorCoverage.complete || interfaceManifest.interfaces.length === 0
      || interfaceManifest.interfaces.every(item => item.direction !== "egress")) {
      throw new Error("Deterministic interface extraction did not inventory the fixture egress interface");
    }
    const forgedResolutionManifestPath = join(coverage, "interface-manifest-forged-resolution.json");
    const forgedResolutionExtractorPath = join(coverage, "interface-extractor-forged-resolution.json");
    const forgedResolutionManifest = structuredClone(interfaceManifest);
    const resolvedCandidate = forgedResolutionManifest.interfaces.find(item => item.discovery_origin_state === "CANDIDATE");
    if (!resolvedCandidate) throw new Error("Fixture lacks a resolved interface candidate");
    delete resolvedCandidate.resolution;
    forgedResolutionManifest.manifest_digest = objectDigest(forgedResolutionManifest);
    await writeFile(forgedResolutionManifestPath, `${JSON.stringify(forgedResolutionManifest, null, 2)}\n`, "utf8");
    run("verify-interface-extractors.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      "--interfaces", forgedResolutionManifestPath,
      "--output", forgedResolutionExtractorPath,
    ], 2);
    const forgedResolutionExtractor = JSON.parse(await readFile(forgedResolutionExtractorPath, "utf8"));
    if (!forgedResolutionExtractor.issues.some(issue => issue.code === "INTERFACE_RESOLUTION_INVALID")) {
      throw new Error("Evidence-free interface candidate resolution was accepted");
    }
    const routingIndexPath = join(coverage, "threat-routing-index.json");
    run("build-threat-routing-index.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      ...functionPaths.flatMap(path => ["--functions", path]),
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
      ...functionPaths.flatMap(path => ["--functions", path]),
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
    for (const [agent, language] of [
      ["python-source-auditor", "python"],
      ["c-cpp-source-auditor", "c-cpp"],
    ]) {
      const output = join(coverage, `${language}-skeleton.audit-report.json`);
      run("initialize-audit-report.mjs", [
        "--audit-id", AUDIT_ID,
        "--round", "1",
        "--agent", agent,
        "--session", `${language}-sink-r1`,
        "--lens", "sink-driven",
        "--language", language,
        "--scope", scopePath,
        ...functionPaths.flatMap(path => ["--functions", path]),
        "--interfaces", interfacesPath,
        "--interface-extractors", interfaceExtractorsPath,
        "--catalog", CATALOG,
        "--threat-model", threatModelPath,
        "--focus-areas", focusAreasPath,
        "--focus-area", "FA-001",
        "--output", output,
      ]);
      const initialized = JSON.parse(await readFile(output, "utf8"));
      const expectedCatalog = catalog.entries.filter(entry => entryAppliesToDomain(entry, language, catalog)).length;
      if (initialized.file_coverage.length === 0 || initialized.function_coverage.length === 0
        || initialized.catalog_coverage.length !== expectedCatalog
        || initialized.catalog_coverage.some(record => !record.catalog_id.startsWith("JW-") || record.status !== "GAP")) {
        throw new Error(`${language} initializer did not use the shared JW catalog selector end to end`);
      }
    }
    run("initialize-audit-report.mjs", [
      "--audit-id", AUDIT_ID,
      "--round", "1",
      "--agent", "ai-security-auditor",
      "--session", "ai-missing-surface-r1",
      "--lens", "sink-driven",
      "--language", "ai",
      "--scope", scopePath,
      ...functionPaths.flatMap(path => ["--functions", path]),
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
      ...functionPaths.flatMap(path => ["--functions", path]),
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
      ...functionPaths.flatMap(path => ["--functions", path]),
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

    const candidateSnapshotDir = join(work, "durable-snapshot-candidate-interface");
    run("snapshot-coverage-inputs.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      ...functionPaths.flatMap(path => ["--functions", path]),
      "--interfaces", rawInterfacesPath,
      "--interface-extractors", rawInterfaceExtractorsPath,
      "--catalog", CATALOG,
      "--threat-model", threatModelPath,
      "--focus-areas", focusAreasPath,
      "--output-dir", candidateSnapshotDir,
    ]);
    const candidateSnapshotIndexPath = join(candidateSnapshotDir, "snapshot-index.json");
    const candidateSnapshot = JSON.parse(await readFile(candidateSnapshotIndexPath, "utf8"));
    const candidatePlanPath = join(coverage, "coverage-plan-candidate-interface.json");
    run("build-coverage-plan.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", candidateSnapshot.scope.path,
      ...candidateSnapshot.functions.flatMap(item => ["--functions", item.path]),
      "--interfaces", candidateSnapshot.interfaces.path,
      "--interface-extractors", candidateSnapshot.interface_extractors.path,
      "--catalog", candidateSnapshot.catalog.path,
      "--focus-areas", candidateSnapshot.semantic.focus_areas.path,
      "--snapshot-index", candidateSnapshotIndexPath,
      "--output", candidatePlanPath,
    ]);
    const candidatePlan = JSON.parse(await readFile(candidatePlanPath, "utf8"));
    const candidateIds = new Set(candidatePlan.inventory.candidate_interface_ids);
    if (candidatePlan.complete || candidatePlan.inventory.bounded
      || candidatePlan.inventory.candidate_interfaces !== rawInterfaceExtractors.interfaces.candidate
      || candidatePlan.summary.unknown !== 0
      || candidatePlan.checks.some(check => check.subject_kind === "interface" && candidateIds.has(check.subject_id))) {
      throw new Error("Unconfirmed interface candidates inflated or disappeared from Coverage Plan accounting");
    }

    const snapshotDir = join(work, "durable-snapshot");
    run("snapshot-coverage-inputs.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      ...functionPaths.flatMap(path => ["--functions", path]),
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

    const missingCatalogFocusPath = join(coverage, "focus-areas-missing-catalog.json");
    const missingCatalogFocus = JSON.parse(await readFile(focusAreasPath, "utf8"));
    delete missingCatalogFocus.manifest_digest;
    const javaAssignment = missingCatalogFocus.focus_areas[0].assignments.find(assignment => assignment.language === "java");
    javaAssignment.catalog_ids = [];
    await writeFile(missingCatalogFocusPath, `${JSON.stringify(missingCatalogFocus, null, 2)}\n`, "utf8");
    run("seal-semantic-manifest.mjs", ["--input", missingCatalogFocusPath]);
    run("snapshot-coverage-inputs.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      ...functionPaths.flatMap(path => ["--functions", path]),
      "--interfaces", interfacesPath,
      "--interface-extractors", interfaceExtractorsPath,
      "--catalog", CATALOG,
      "--threat-model", threatModelPath,
      "--focus-areas", missingCatalogFocusPath,
      "--output-dir", join(work, "snapshot-missing-catalog"),
    ], 1);

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

    const staleGapReports = join(work, "reports-stale-gap");
    await cp(positiveReports, staleGapReports, { recursive: true });
    const staleGapReportPath = join(staleGapReports, "web-source-auditor.sink-driven.audit-report.json");
    const staleGapReport = JSON.parse(await readFile(staleGapReportPath, "utf8"));
    if (!staleGapReport.file_coverage[0]) throw new Error("Stale-gap fixture has no web file coverage record");
    staleGapReport.file_coverage[0].gap_reason = "stale-gap-reason-must-not-survive-closure";
    await writeFile(staleGapReportPath, `${JSON.stringify(staleGapReport, null, 2)}\n`, "utf8");
    const staleGapOutput = join(coverage, "verification-stale-gap.json");
    run("verify-coverage.mjs", [...commonVerifyArgs, "--reports-dir", staleGapReports, "--output", staleGapOutput], 2);
    const staleGap = JSON.parse(await readFile(staleGapOutput, "utf8"));
    if (staleGap.complete
      || !staleGap.invalid.files.some(item => item.errors.includes("closed-record-has-gap-reason"))
      || !staleGap.finding_intake.quarantined_reports.some(item => item.report_path === staleGapReportPath
        && item.issue_codes.includes("INVALID_FILE_COVERAGE_RECORD"))) {
      throw new Error("Closed coverage record with a stale gap_reason was not quarantined");
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
      "--snapshot-index", snapshotIndexPath,
      "--output", coveragePlanPath,
    ]);
    const coveragePlan = JSON.parse(await readFile(coveragePlanPath, "utf8"));
    if (!coveragePlan.complete || coveragePlan.summary.required === 0
      || coveragePlan.summary.catalog_domain_required === 0 || coveragePlan.summary.interface_required === 0
      || coveragePlan.execution_model !== "assignment-unit-v1"
      || coveragePlan.coverage_policy?.mode !== "observe"
      || coveragePlan.coverage_units?.length === 0
      || validatePlan(coveragePlan).length > 0) {
      throw new Error("Coverage Plan v3 did not produce a complete sparse catalog/interface check universe");
    }
    if (coveragePlan.coverage_units.reduce((sum, unit) => sum + unit.required_check_count, 0)
      !== coveragePlan.summary.required) {
      throw new Error("Assignment coverage units do not partition the required check universe exactly once");
    }
    const unitLedgerPath = join(coverage, "coverage-ledger-unit-observe.jsonl");
    await initializeLedger({ planPath: coveragePlanPath, ledgerPath: unitLedgerPath });
    const unit = coveragePlan.coverage_units[0];
    await expectReject(() => beginCoverageUnit({
      planPath: coveragePlanPath,
      ledgerPath: unitLedgerPath,
      unitId: unit.unit_id,
      sessionId: "fixture-unit-unauthorized-session",
      agentName: unit.agent_name === "ai-security-auditor" ? "web-source-auditor" : "ai-security-auditor",
      idempotencyKey: "fixture-unit-unauthorized",
    }), /not authorized/);
    const unitAssignment = await beginCoverageUnit({
      planPath: coveragePlanPath,
      ledgerPath: unitLedgerPath,
      unitId: unit.unit_id,
      sessionId: "fixture-unit-session",
      agentName: unit.agent_name,
      idempotencyKey: "fixture-unit-begin",
    });
    const sinkGapId = unit.check_ids.find(checkId => coveragePlan.checks.find(check => check.check_id === checkId)?.lens === "sink-driven");
    await submitCoverageUnitAttestation({
      planPath: coveragePlanPath,
      ledgerPath: unitLedgerPath,
      unitId: unit.unit_id,
      sessionId: "fixture-unit-session",
      assignmentToken: unitAssignment.assignment_token,
      idempotencyKey: "fixture-unit-partial",
      completedLenses: ["sink-driven"],
      state: "PARTIAL",
      gapCheckIds: [sinkGapId],
      sourceScope: "required",
      queryOrRule: "fixture-unit-sink-pass",
      tool: "fixture-unit-review",
      toolVersion: "1.0.0",
      resultPayload: "fixture-unit-partial-result",
      resultDigest: sha256("fixture-unit-partial-result"),
      resultSummary: "Sink lens complete except one explicit gap.",
    });
    const partialUnitVerification = await verifyLedger({
      planPath: coveragePlanPath,
      ledgerPath: unitLedgerPath,
      requireFinalized: false,
    });
    if (partialUnitVerification.state.get(sinkGapId)?.execution_state !== "GAP"
      || !unit.check_ids.some(checkId => partialUnitVerification.state.get(checkId)?.execution_state === "VERIFIED")
      || !unit.check_ids.some(checkId => partialUnitVerification.state.get(checkId)?.execution_state === "PLANNED")) {
      throw new Error("Partial unit attestation did not preserve all-minus-gaps lens state");
    }
    await submitCoverageUnitAttestation({
      planPath: coveragePlanPath,
      ledgerPath: unitLedgerPath,
      unitId: unit.unit_id,
      sessionId: "fixture-unit-session",
      assignmentToken: unitAssignment.assignment_token,
      idempotencyKey: "fixture-unit-other-lenses",
      completedLenses: ["control-driven", "config-driven"],
      state: "PARTIAL",
      gapCheckIds: [],
      sourceScope: "required",
      queryOrRule: "fixture-unit-other-lenses",
      tool: "fixture-unit-review",
      toolVersion: "1.0.0",
      resultPayload: "fixture-unit-other-lenses-result",
      resultDigest: sha256("fixture-unit-other-lenses-result"),
      resultSummary: "Control and config lenses complete.",
    });
    await submitCoverageUnitAttestation({
      planPath: coveragePlanPath,
      ledgerPath: unitLedgerPath,
      unitId: unit.unit_id,
      sessionId: "fixture-unit-session",
      assignmentToken: unitAssignment.assignment_token,
      idempotencyKey: "fixture-unit-gap-repair",
      completedLenses: ["sink-driven"],
      state: "PARTIAL",
      gapCheckIds: [],
      sourceScope: "required",
      queryOrRule: "fixture-unit-sink-repair",
      tool: "fixture-unit-review",
      toolVersion: "1.0.0",
      resultPayload: "fixture-unit-gap-repair-result",
      resultDigest: sha256("fixture-unit-gap-repair-result"),
      resultSummary: "The prior sink gap was repaired.",
    });
    const postUnitInspection = await inspectSubject({
      planPath: coveragePlanPath,
      ledgerPath: unitLedgerPath,
      checkId: sinkGapId,
      sessionId: "fixture-post-unit-finding-session",
      agentName: unit.agent_name,
      idempotencyKey: "fixture-post-unit-inspect",
    });
    const postUnitReceipt = await recordToolResult({
      planPath: coveragePlanPath,
      ledgerPath: unitLedgerPath,
      checkId: sinkGapId,
      sessionId: "fixture-post-unit-finding-session",
      assignmentToken: postUnitInspection.assignment_token,
      idempotencyKey: "fixture-post-unit-receipt",
      sourceScope: "required",
      locators: [{
        kind: "required-source-set",
        check_id: sinkGapId,
        source_set_id: coveragePlan.checks.find(check => check.check_id === sinkGapId).required_source_set_id,
        source_count: coveragePlan.checks.find(check => check.check_id === sinkGapId).required_source_count,
      }],
      queryOrRule: "fixture-post-unit-exact-result",
      tool: "fixture-unit-review",
      toolVersion: "1.0.0",
      resultPayload: "fixture-post-unit-exact-result",
    });
    await submitDecision({
      planPath: coveragePlanPath,
      ledgerPath: unitLedgerPath,
      checkId: sinkGapId,
      sessionId: "fixture-post-unit-finding-session",
      assignmentToken: postUnitInspection.assignment_token,
      idempotencyKey: "fixture-post-unit-decision",
      executionState: "VERIFIED",
      resultState: "NO_FINDING",
      receiptIds: [postUnitReceipt.receipt.receipt_id],
      rationale: "Coverage execution and exact result binding remain independently writable.",
    });
    await finalizeLedger({
      planPath: coveragePlanPath,
      ledgerPath: unitLedgerPath,
      idempotencyKey: "fixture-unit-observe-finalize",
    });
    const observedVerification = await verifyLedger({
      planPath: coveragePlanPath,
      ledgerPath: unitLedgerPath,
      requireFinalized: false,
      requirePolicyFinalized: true,
    });
    if (!observedVerification.policy_satisfied || observedVerification.complete
      || observedVerification.seal_state !== "FINALIZED_OBSERVED"
      || unit.check_ids.some(checkId => observedVerification.state.get(checkId)?.execution_state !== "VERIFIED")) {
      throw new Error("Observe policy did not finish independently from strict coverage completion");
    }
    const observedSummaryPath = join(coverage, "coverage-summary-unit-observe.json");
    run("render-coverage-summary.mjs", [
      "--mode", "policy",
      "--plan", coveragePlanPath,
      "--ledger", unitLedgerPath,
      "--structural", positiveOutput,
      "--output", observedSummaryPath,
      "--markdown-output", join(coverage, "coverage-summary-unit-observe.md"),
    ]);
    const observedSummary = JSON.parse(await readFile(observedSummaryPath, "utf8"));
    if (!observedSummary.policy_satisfied || observedSummary.complete
      || observedSummary.policy_mode !== "observe"
      || observedSummary.execution.complete_units !== 1) {
      throw new Error("Policy summary did not separate workflow acceptance from strict coverage completeness");
    }
    const observedGatePath = join(coverage, "coverage-verification-unit-observe.json");
    run("verify-coverage-v3.mjs", [
      "--mode", "policy",
      ...commonVerifyArgs,
      "--reports-dir", positiveReports,
      "--plan", coveragePlanPath,
      "--ledger", unitLedgerPath,
      "--structural-output", join(coverage, "coverage-structural-unit-observe.json"),
      "--summary-output", join(coverage, "coverage-summary-unit-observe-gate.json"),
      "--markdown-output", join(coverage, "coverage-summary-unit-observe-gate.md"),
      "--output", observedGatePath,
    ]);
    const observedGate = JSON.parse(await readFile(observedGatePath, "utf8"));
    if (!observedGate.policy_satisfied || observedGate.complete
      || observedGate.seal_state !== "FINALIZED_OBSERVED" || observedGate.gaps.length === 0) {
      throw new Error("Policy gate did not accept observe mode while retaining strict coverage gaps");
    }
    const releasePlan = structuredClone(coveragePlan);
    releasePlan.coverage_policy.mode = "release";
    if (releasePlan.coverage_policy.release_required_unit_ids.length === releasePlan.coverage_units.length) {
      releasePlan.coverage_units.at(-1).policy_tags = [];
      releasePlan.coverage_policy.release_required_unit_ids = releasePlan.coverage_units
        .filter(item => item.policy_tags.length > 0).map(item => item.unit_id).sort();
    }
    if (releasePlan.coverage_policy.release_required_unit_ids.length === 0) {
      releasePlan.coverage_units[0].policy_tags = ["identity-or-privilege"];
      releasePlan.coverage_policy.release_required_unit_ids = [releasePlan.coverage_units[0].unit_id];
    }
    releasePlan.manifest_digest = objectDigest(releasePlan);
    const releasePlanPath = join(coverage, "coverage-plan-release.json");
    const releaseLedgerPath = join(coverage, "coverage-ledger-release.jsonl");
    await writeFile(releasePlanPath, `${JSON.stringify(releasePlan, null, 2)}\n`, "utf8");
    await initializeLedger({ planPath: releasePlanPath, ledgerPath: releaseLedgerPath });
    for (const releaseUnitId of releasePlan.coverage_policy.release_required_unit_ids) {
      const releaseUnit = releasePlan.coverage_units.find(item => item.unit_id === releaseUnitId);
      const assignment = await beginCoverageUnit({
        planPath: releasePlanPath,
        ledgerPath: releaseLedgerPath,
        unitId: releaseUnitId,
        sessionId: "fixture-release-session",
        agentName: releaseUnit.agent_name,
        idempotencyKey: `release-begin-${releaseUnitId}`,
      });
      await submitCoverageUnitAttestation({
        planPath: releasePlanPath,
        ledgerPath: releaseLedgerPath,
        unitId: releaseUnitId,
        sessionId: "fixture-release-session",
        assignmentToken: assignment.assignment_token,
        idempotencyKey: `release-attest-${releaseUnitId}`,
        completedLenses: LENSES,
        state: "COMPLETE",
        gapCheckIds: [],
        sourceScope: "required",
        queryOrRule: "fixture-release-policy-review",
        tool: "fixture-unit-review",
        toolVersion: "1.0.0",
        resultPayload: `release:${releaseUnitId}`,
        resultSummary: "Policy-tagged unit complete.",
      });
    }
    await finalizeLedger({
      planPath: releasePlanPath,
      ledgerPath: releaseLedgerPath,
      idempotencyKey: "fixture-release-finalize",
    });
    const releaseVerification = await verifyLedger({
      planPath: releasePlanPath,
      ledgerPath: releaseLedgerPath,
      requireFinalized: false,
      requirePolicyFinalized: true,
    });
    if (!releaseVerification.policy_satisfied || releaseVerification.complete
      || releaseVerification.seal_state !== "FINALIZED_RELEASE" || releaseVerification.gaps.length === 0) {
      throw new Error("Release policy did not gate only its policy-tagged coverage units");
    }
    const groupedInterfaceChecks = coveragePlan.checks.filter(check => check.subject_kind === "interface" && check.applicability === "REQUIRED");
    if (coveragePlan.summary.not_applicable !== 0
      || groupedInterfaceChecks.some(check => !check.subject_id.startsWith("interface-group:")
        || !Array.isArray(check.required_interface_ids) || check.required_interface_ids.length === 0)
      || coveragePlan.summary.interface_memberships_required
        !== groupedInterfaceChecks.reduce((sum, check) => sum + check.required_interface_ids.length, 0)) {
      throw new Error("Coverage Plan expanded sparse grouped interface work back into per-interface applicability rows");
    }
    const requiredChecks = coveragePlan.checks.filter(check => check.applicability === "REQUIRED");
    if (coveragePlan.checks.some(check => Object.hasOwn(check, "required_source_file_ids"))
      || coveragePlan.source_sets.length >= requiredChecks.length
      || requiredChecks.some(check => !coveragePlan.source_sets.some(sourceSet =>
        sourceSet.source_set_id === check.required_source_set_id
        && sourceSet.file_ids.length === check.required_source_count))) {
      throw new Error("Coverage Plan did not normalize repeated source universes into shared source sets");
    }
    run("build-coverage-plan.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      ...snapshotFunctionPaths.flatMap(path => ["--functions", path]),
      "--interfaces", snapshotInterfacesPath,
      "--interface-extractors", snapshotInterfaceExtractorsPath,
      "--catalog", snapshotCatalogPath,
      "--focus-areas", snapshotIndex.semantic.focus_areas.path,
      "--snapshot-index", snapshotIndexPath,
      "--output", join(coverage, "coverage-plan-stale-input.json"),
    ], 1);
    const legacyPlanPath = join(coverage, "coverage-plan-v2-rejected.json");
    const legacyPlan = structuredClone(coveragePlan);
    legacyPlan.schema_version = 2;
    legacyPlan.coverage_model_version = "coverage-v2";
    legacyPlan.manifest_digest = objectDigest(legacyPlan);
    await writeFile(legacyPlanPath, `${JSON.stringify(legacyPlan, null, 2)}\n`, "utf8");
    const legacyPlanErrors = validatePlan(legacyPlan);
    if (!legacyPlanErrors.some(error => error.includes("schema_version must be 3"))
      || !legacyPlanErrors.some(error => error.includes("coverage_model_version must be coverage-v3"))) {
      throw new Error("Coverage Plan v2 was not explicitly rejected by the v3 contract");
    }
    await expectReject(() => initializeLedger({
      planPath: legacyPlanPath,
      ledgerPath: join(coverage, "coverage-ledger-v2-rejected.jsonl"),
    }), /schema_version must be 3/);
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
    const terminalPartialLedgerPath = join(coverage, "coverage-ledger-terminal-partial.jsonl");
    await initializeLedger({ planPath: coveragePlanPath, ledgerPath: terminalPartialLedgerPath });
    await finalizePartialLedger({
      planPath: coveragePlanPath,
      ledgerPath: terminalPartialLedgerPath,
      idempotencyKey: "fixture-terminal-partial",
      terminationReason: "round-limit-reached",
    });
    const terminalPartialVerification = await verifyLedger({
      planPath: coveragePlanPath,
      ledgerPath: terminalPartialLedgerPath,
      requireFinalized: false,
    });
    if (terminalPartialVerification.seal_state !== "FINALIZED_PARTIAL" || terminalPartialVerification.complete
      || terminalPartialVerification.gaps.length === 0) {
      throw new Error("Terminal partial ledger did not preserve explicit incomplete coverage");
    }
    await expectReject(() => checkpointLedger({
      planPath: coveragePlanPath,
      ledgerPath: terminalPartialLedgerPath,
      idempotencyKey: "terminal-partial-mutation",
      label: "must-fail",
    }), /finalized and immutable/);
    const firstRequiredCheck = coveragePlan.checks.find(check => check.applicability === "REQUIRED");
    await expectReject(() => inspectSubject({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: "check:forged",
      sessionId: "fixture-ledger-session",
      agentName: DOMAIN_AGENTS[firstRequiredCheck.domain],
      idempotencyKey: "fake-check",
    }), /Unknown coverage check_id/);
    const firstInspection = await inspectSubject({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-ledger-session",
      agentName: DOMAIN_AGENTS[firstRequiredCheck.domain],
      idempotencyKey: "first-inspection",
    });
    await expectReject(() => recordToolResult({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-ledger-session",
      assignmentToken: "forged-assignment-token-that-is-long-enough",
      idempotencyKey: "forged-assignment-receipt",
      sourceScope: "required",
      locators: [{
        kind: "required-source-set",
        check_id: firstRequiredCheck.check_id,
        source_set_id: firstRequiredCheck.required_source_set_id,
        source_count: firstRequiredCheck.required_source_count,
      }],
      queryOrRule: "fixture-negative-search",
      tool: "fixture",
      toolVersion: "1",
      resultPayload: "forged",
    }), /Assignment token is missing/);
    await expectReject(() => recordToolResult({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-ledger-session",
      assignmentToken: firstInspection.assignment_token,
      idempotencyKey: "mismatched-result-digest",
      sourceScope: "required",
      locators: [{
        kind: "required-source-set",
        check_id: firstRequiredCheck.check_id,
        source_set_id: firstRequiredCheck.required_source_set_id,
        source_count: firstRequiredCheck.required_source_count,
      }],
      queryOrRule: "fixture-negative-search",
      tool: "fixture",
      toolVersion: "1",
      resultPayload: "server-derived-result",
      resultDigest: "0".repeat(64),
    }), /does not match the server-derived result attestation/);
    await expectReject(() => submitDecision({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-ledger-session",
      assignmentToken: firstInspection.assignment_token,
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
      assignmentToken: firstInspection.assignment_token,
      idempotencyKey: "agent-na",
      executionState: "N/A",
      resultState: "INCONCLUSIVE",
      rationale: "invalid agent N/A",
    }), /N\/A is planner-only/);
    const delegated = await delegateAssignment({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-ledger-session",
      assignmentToken: firstInspection.assignment_token,
      targetSessionId: "fixture-delegated-session",
      idempotencyKey: "delegate-first-check",
    });
    await expectReject(() => recordToolResult({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-delegated-session",
      assignmentToken: firstInspection.assignment_token,
      idempotencyKey: "undelegated-token",
      sourceScope: "required",
      locators: [{
        kind: "required-source-set",
        check_id: firstRequiredCheck.check_id,
        source_set_id: firstRequiredCheck.required_source_set_id,
        source_count: firstRequiredCheck.required_source_count,
      }],
      queryOrRule: "fixture-delegation-negative",
      tool: "fixture",
      toolVersion: "1",
      resultPayload: "negative",
    }), /not authorized for this session/);
    if (!delegated.assignment_token) throw new Error("Explicit delegation did not issue a new assignment token");
    const delegatedReceipt = await recordToolResult({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-delegated-session",
      assignmentToken: delegated.assignment_token,
      idempotencyKey: "delegated-receipt",
      sourceScope: "required",
      locators: [{
        kind: "required-source-set",
        check_id: firstRequiredCheck.check_id,
        source_set_id: firstRequiredCheck.required_source_set_id,
        source_count: firstRequiredCheck.required_source_count,
      }],
      queryOrRule: "fixture-delegation-positive",
      tool: "fixture",
      toolVersion: "1",
      resultPayload: "delegated-result",
    });
    const independentInspection = await inspectSubject({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-independent-session",
      agentName: DOMAIN_AGENTS[firstRequiredCheck.domain],
      idempotencyKey: "independent-inspection",
    });
    await expectReject(() => submitDecision({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-independent-session",
      assignmentToken: independentInspection.assignment_token,
      idempotencyKey: "cross-assignment-receipt",
      executionState: "VERIFIED",
      resultState: "NO_FINDING",
      receiptIds: [delegatedReceipt.receipt.receipt_id],
      rationale: "A separately inspected assignment must not reuse a delegated receipt.",
    }), /Receipt is missing, stale, unauthorized, or belongs to another check/);

    const findingId = "FIND-COVERAGE-FIXTURE-001";
    const findingArtifactPath = join(coverage, "finding-coverage-fixture-001.json");
    const invalidFindingArtifactPath = join(coverage, "finding-coverage-fixture-invalid.json");
    await writeFile(findingArtifactPath, `${JSON.stringify(ledgerFindingArtifact(findingId, firstRequiredCheck, coveragePlan), null, 2)}\n`, "utf8");
    await writeFile(invalidFindingArtifactPath, `${JSON.stringify(ledgerFindingArtifact("FIND-DIFFERENT", firstRequiredCheck, coveragePlan), null, 2)}\n`, "utf8");

    for (const check of coveragePlan.checks.filter(item => item.applicability === "REQUIRED")) {
      const inspection = await inspectSubject({
        planPath: coveragePlanPath,
        ledgerPath,
        checkId: check.check_id,
        sessionId: "fixture-ledger-session",
        agentName: DOMAIN_AGENTS[check.domain],
        idempotencyKey: `inspect-${check.check_id}`,
      });
      const resultPayload = `result:${check.check_id}`;
      const receipt = await recordToolResult({
        planPath: coveragePlanPath,
        ledgerPath,
        checkId: check.check_id,
        sessionId: "fixture-ledger-session",
        assignmentToken: inspection.assignment_token,
        idempotencyKey: `receipt-${check.check_id}`,
        sourceScope: "required",
        locators: [{
          kind: "required-source-set",
          source_set_id: check.required_source_set_id,
          source_count: check.required_source_count,
          check_id: check.check_id,
        }],
        queryOrRule: `fixture-review:${check.vulnerability_type_id}:${check.lens}`,
        tool: "fixture-deterministic-review",
        toolVersion: "1.0.0",
        resultPayload,
        resultDigest: sha256(resultPayload),
        resultSummary: "No fixture finding.",
      });
      if (receipt.receipt.source_set?.mode !== "required-source-set"
        || receipt.receipt.source_set.source_set_id !== check.required_source_set_id
        || receipt.receipt.source_set.source_count !== sourceFileIdsForCheck(coveragePlan, check).length
        || !/^[a-f0-9]{64}$/.test(receipt.receipt.source_set.source_set_sha256 ?? "")
        || receipt.receipt.result_attestation?.sha256 !== sha256(resultPayload)) {
        throw new Error("Required source universe was not represented by a compact digest-bound source set");
      }
      if (check.check_id === firstRequiredCheck.check_id) {
        await expectReject(() => submitDecision({
          planPath: coveragePlanPath,
          ledgerPath,
          checkId: check.check_id,
          sessionId: "fixture-ledger-session",
          assignmentToken: inspection.assignment_token,
          idempotencyKey: `invalid-finding-${check.check_id}`,
          executionState: "VERIFIED",
          resultState: "FINDING",
          receiptIds: [receipt.receipt.receipt_id],
          findingIds: [findingId],
          findingArtifacts: [{ finding_id: findingId, path: invalidFindingArtifactPath }],
          rationale: "This forged finding artifact must be rejected.",
        }), /Finding artifact violates v2 contract: finding-id-mismatch/);
      }
      await submitDecision({
        planPath: coveragePlanPath,
        ledgerPath,
        checkId: check.check_id,
        sessionId: "fixture-ledger-session",
        assignmentToken: inspection.assignment_token,
        idempotencyKey: `decision-${check.check_id}`,
        executionState: "VERIFIED",
        resultState: check.check_id === firstRequiredCheck.check_id ? "FINDING" : "NO_FINDING",
        receiptIds: [receipt.receipt.receipt_id],
        findingIds: check.check_id === firstRequiredCheck.check_id ? [findingId] : [],
        findingArtifacts: check.check_id === firstRequiredCheck.check_id
          ? [{ finding_id: findingId, path: findingArtifactPath }]
          : [],
        rationale: "Digest-bound fixture evidence reviewed.",
      });
    }
    await expectReject(() => inspectSubject({
      planPath: coveragePlanPath,
      ledgerPath,
      checkId: firstRequiredCheck.check_id,
      sessionId: "fixture-post-verified-session",
      agentName: DOMAIN_AGENTS[firstRequiredCheck.domain],
      idempotencyKey: "post-verified-inspection",
    }), /VERIFIED decision is immutable/);
    const checkpoint = JSON.parse(run("checkpoint-coverage-ledger.mjs", [
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--idempotency-key", "fixture-checkpoint",
      "--label", "pre-final",
    ]).stdout);
    if (!checkpoint.checkpointed || checkpoint.seal_state !== "PARTIAL_CHECKPOINT" || checkpoint.complete) {
      throw new Error("Checkpoint CLI did not preserve a nonterminal ledger state");
    }
    const preFinalSummaryPath = join(coverage, "coverage-summary-pre-final.json");
    const preFinalMarkdownPath = join(coverage, "coverage-summary-pre-final.md");
    run("render-coverage-summary.mjs", [
      "--mode", "partial",
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural", positiveOutput,
      "--output", preFinalSummaryPath,
      "--markdown-output", preFinalMarkdownPath,
    ], 2);
    const preFinalSummary = JSON.parse(await readFile(preFinalSummaryPath, "utf8"));
    if (preFinalSummary.complete || preFinalSummary.coverage_status !== "PARTIAL"
      || preFinalSummary.seal_state !== "PARTIAL_CHECKPOINT") {
      throw new Error("A bounded all-verified partial checkpoint was incorrectly reported as finalized coverage");
    }
    await finalizeLedger({ planPath: coveragePlanPath, ledgerPath, idempotencyKey: "fixture-finalize" });
    const ledgerVerification = await verifyLedger({ planPath: coveragePlanPath, ledgerPath, requireFinalized: true });
    if (!ledgerVerification.complete || ledgerVerification.gaps.length > 0 || ledgerVerification.seal_state !== "FINALIZED_COMPLETE") {
      throw new Error("Completed Coverage Ledger v3 did not verify");
    }
    if (ledgerVerification.finalization.findings !== 1) {
      throw new Error("Artifact-bound finding was not preserved in finalized ledger accounting");
    }

    const attestedReportPath = join(positiveReports, `${DOMAIN_AGENTS[firstRequiredCheck.domain]}.${firstRequiredCheck.lens}.audit-report.json`);
    const attestedReport = JSON.parse(await readFile(attestedReportPath, "utf8"));
    const attestedFinding = JSON.parse(await readFile(findingArtifactPath, "utf8"));
    const attestedCatalogRecord = attestedReport.catalog_coverage.find(record => record.catalog_id === firstRequiredCheck.vulnerability_type_id
      && record.domain === firstRequiredCheck.domain);
    if (!attestedCatalogRecord) throw new Error("Coverage finding fixture could not locate the report catalog record for its Ledger check");
    attestedCatalogRecord.status = "FINDING";
    attestedCatalogRecord.finding_ids = [findingId];
    attestedReport.finding_schema_version = 2;
    attestedReport.findings = [attestedFinding];
    await writeFile(attestedReportPath, `${JSON.stringify(attestedReport, null, 2)}\n`, "utf8");
    run("reconcile-audit-report.mjs", ["--report", attestedReportPath, "--scope", snapshotScopePath, "--catalog", snapshotCatalogPath]);

    const v3Output = join(coverage, "coverage-verification-v3.json");
    const v3StructuralOutput = join(coverage, "coverage-structural-v3.json");
    const summaryPath = join(coverage, "coverage-summary.json");
    const summaryMarkdownPath = join(coverage, "coverage-summary.md");
    run("verify-coverage-v3.mjs", [
      ...commonVerifyArgs,
      "--reports-dir", positiveReports,
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural-output", v3StructuralOutput,
      "--summary-output", summaryPath,
      "--markdown-output", summaryMarkdownPath,
      "--output", v3Output,
    ]);
    const v3Verification = JSON.parse(await readFile(v3Output, "utf8"));
    if (!v3Verification.complete
      || v3Verification.summary.accounting.known_coverage.percentage !== 100
      || v3Verification.summary.external_interfaces.complete_interfaces.percentage !== 100
      || v3Verification.seal_state !== "FINALIZED_COMPLETE"
      || v3Verification.finding_reconciliation.accepted_report_findings !== 1
      || v3Verification.finding_reconciliation.ledger_finding_artifacts !== 1) {
      throw new Error("Coverage v3 final gate did not derive complete ledger/interface statistics");
    }

    const adjudicationInputPath = join(coverage, "finding-input.json");
    runAdjudication("build-adjudication-input.mjs", [
      "--audit-id", AUDIT_ID,
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural", v3StructuralOutput,
      "--output", adjudicationInputPath,
    ]);
    const adjudicationInput = JSON.parse(await readFile(adjudicationInputPath, "utf8"));
    if (adjudicationInput.candidates.length !== 1
      || adjudicationInput.candidates[0].finding_id !== findingId
      || adjudicationInput.candidates[0].primary_check_id !== firstRequiredCheck.check_id) {
      throw new Error("Adjudication input did not preserve the structurally accepted, Ledger-attested finding");
    }

    const unattestedReports = join(work, "reports-unattested-finding");
    await cp(positiveReports, unattestedReports, { recursive: true });
    const unattestedReportPath = join(unattestedReports, `${DOMAIN_AGENTS[firstRequiredCheck.domain]}.${firstRequiredCheck.lens}.audit-report.json`);
    const unattestedReport = JSON.parse(await readFile(unattestedReportPath, "utf8"));
    const unattestedFinding = structuredClone(attestedFinding);
    unattestedFinding.finding_id = "FIND-COVERAGE-FIXTURE-UNATTESTED";
    const unattestedCatalogRecord = unattestedReport.catalog_coverage.find(record => record.catalog_id === firstRequiredCheck.vulnerability_type_id
      && record.domain === firstRequiredCheck.domain);
    unattestedCatalogRecord.finding_ids = [unattestedFinding.finding_id];
    unattestedReport.findings = [unattestedFinding];
    await writeFile(unattestedReportPath, `${JSON.stringify(unattestedReport, null, 2)}\n`, "utf8");
    run("reconcile-audit-report.mjs", ["--report", unattestedReportPath, "--scope", snapshotScopePath, "--catalog", snapshotCatalogPath]);
    const unattestedV3Output = join(coverage, "coverage-verification-unattested-finding.json");
    run("verify-coverage-v3.mjs", [
      ...commonVerifyArgs,
      "--reports-dir", unattestedReports,
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural-output", join(coverage, "coverage-structural-unattested-finding.json"),
      "--summary-output", join(coverage, "coverage-summary-unattested-finding.json"),
      "--markdown-output", join(coverage, "coverage-summary-unattested-finding.md"),
      "--output", unattestedV3Output,
    ], 2);
    const unattestedV3 = JSON.parse(await readFile(unattestedV3Output, "utf8"));
    if (!unattestedV3.issues.some(issue => issue.code === "UNATTESTED_REPORT_FINDING")
      || !unattestedV3.issues.some(issue => issue.code === "ORPHAN_LEDGER_FINDING")) {
      throw new Error("Coverage v3 did not reject the un-attested report finding and orphaned Ledger finding");
    }
    runAdjudication("build-adjudication-input.mjs", [
      "--audit-id", AUDIT_ID,
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural", join(coverage, "coverage-structural-unattested-finding.json"),
      "--output", join(coverage, "finding-input-unattested.json"),
    ], 1);
    run("verify-coverage-summary.mjs", [
      "--summary", summaryPath,
      "--markdown", summaryMarkdownPath,
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural", v3StructuralOutput,
    ]);

    const adjudicationPath = join(coverage, "finding-adjudication.json");
    const adjudicationCandidate = adjudicationInput.candidates[0];
    const adjudication = {
      schema_version: 1,
      audit_id: AUDIT_ID,
      scope_digest: scope.scope_digest,
      input_manifest_digest: adjudicationInput.manifest_digest,
      adjudicator_session_id: "coverage-fixture-adjudicator-r1",
      decisions: [{
        finding_id: findingId,
        finding_object_digest: adjudicationCandidate.finding_object_digest,
        state: "SUPPORTED_STATIC",
        decision_rationale: "The fixture source reaches its evidence-backed security operation with no effective guard.",
        attack_surface_review: {
          disposition: "LIMITED",
          reviewed_fields: ["in_scope", "exposure", "vector", "auth_scope", "preconditions", "identities", "boundary_crossing", "impact", "target_reach", "controls", "counterevidence", "blindspots", "confidence"],
          rationale: "The fixture's static attack-surface facts are supported, but its deployment precondition remains unverified.",
          evidence: ["Finding evidence facts 0 and 1 and all four guard scopes were reviewed."],
          limitations: ["The fixture has no runtime deployment evidence."],
        },
        semantic_proof: {
          source_fact_indexes: [0],
          sink_or_config_fact_indexes: [1],
          framework: {
            component: "coverage-fixture",
            version_or_commit: "fixture",
            api_or_configuration: "Fixture security operation",
            evidence: ["The fixture source and sink facts were independently reviewed."],
          },
          path: {
            state: "PROVEN",
            steps: ["Fixture source reaches the fixture security operation."],
          },
          security_effect: {
            state: "PROVEN",
            rationale: "The fixture establishes a static security-relevant effect.",
          },
        },
        guards: ["local", "inherited", "global", "deployment"].map(scopeName => ({
          scope: scopeName,
          state: "ABSENT",
          effective_for_claim: false,
          rationale: `Fixture has no ${scopeName} guard.`,
          evidence: [`${scopeName} guard search completed.`],
        })),
        counterclaim: {
          claim: "An effective guard prevents the fixture security effect.",
          outcome: "REFUTED",
          evidence: ["No effective fixture guard was found."],
        },
        contradiction_refs: [],
        blocking_questions: [],
      }],
    };
    adjudication.manifest_digest = candidateManifestDigest(adjudication);
    await writeFile(adjudicationPath, `${JSON.stringify(adjudication, null, 2)}\n`, "utf8");
    const cvssClaimsPath = join(coverage, "cvss-claims.json");
    const cvssClaims = {
      schema_version: 1,
      audit_id: AUDIT_ID,
      scope_digest: scope.scope_digest,
      adjudication_manifest_digest: adjudication.manifest_digest,
      assessments: [{
        finding_id: findingId,
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        rationale: "The fixture is remotely reachable without privileges or interaction and proves all three base impacts.",
        assumptions: ["The fixture's static route is deployed as its source configuration describes."],
        evidence_refs: ["decision:0", "fixture-source-and-sink"],
      }],
    };
    await writeFile(cvssClaimsPath, `${JSON.stringify(cvssClaims, null, 2)}\n`, "utf8");
    const cvssAssessmentPath = join(coverage, "cvss-assessment.json");
    const cvssAssessment = buildCvssAssessmentManifest(cvssClaims, adjudication);
    await writeFile(cvssAssessmentPath, `${JSON.stringify(cvssAssessment, null, 2)}\n`, "utf8");
    run(resolve(ADJUDICATION_SCRIPTS, "validate-cvss-assessment.mjs"), [
      "--adjudication", adjudicationPath,
      "--assessment", cvssAssessmentPath,
    ]);
    run(resolve(ADJUDICATION_SCRIPTS, "build-empty-cvss-assessment.mjs"), [
      "--adjudication", adjudicationPath,
      "--output", join(coverage, "cvss-assessment-invalid-empty.json"),
    ], 1);
    run(resolve(ADJUDICATION_SCRIPTS, "build-empty-finding-adjudication.mjs"), [
      "--input", adjudicationInputPath,
      "--session-id", "invalid-nonempty-fixture",
      "--output", join(coverage, "adjudication-invalid-empty.json"),
    ], 1);
    const attackChainsPath = join(coverage, "attack-chains.json");
    const attackChains = {
      schema_version: 2,
      audit_id: AUDIT_ID,
      scope_digest: scope.scope_digest,
      adjudication_manifest_digest: adjudication.manifest_digest,
      chains: [{
        chain_id: "CHAIN-COVERAGE-FIXTURE-001",
        assessment_state: "SUPPORTED_STATIC",
        steps: [{
          step_id: "S1",
          claim: "The adjudicated fixture finding establishes the first security-relevant transition.",
          evidence_state: "SUPPORTED_STATIC",
          evidence_refs: [findingId],
          blocking_gap_ids: [],
        }],
        transitions: [],
        first_blocking_step_id: null,
      }],
      gaps: [],
      chain_accounting: {
        raw_chain_ids: ["CHAIN-COVERAGE-FIXTURE-001"],
        accepted_chain_ids: ["CHAIN-COVERAGE-FIXTURE-001"],
        rejected_chain_ids: [],
      },
    };
    attackChains.manifest_digest = attackChainManifestDigest(attackChains);
    await writeFile(attackChainsPath, `${JSON.stringify(attackChains, null, 2)}\n`, "utf8");
    run(resolve(REPOSITORY, ".opencode/skills/attack-chain-subagent/system-attack-chain-hunting/scripts/build-empty-attack-chain-report.mjs"), [
      "--adjudication", adjudicationPath,
      "--output", join(coverage, "attack-chains-invalid-empty.json"),
    ], 1);
    const finalReportModelPath = join(coverage, "final-report-model.json");
    const finalReportPath = join(coverage, "security-audit-report.fixture.md");
    run("build-final-report-model.mjs", [
      "--audit-id", AUDIT_ID,
      "--mode", "final",
      "--coverage-summary", summaryPath,
      "--adjudication-input", adjudicationInputPath,
      "--adjudication", adjudicationPath,
      "--cvss", cvssAssessmentPath,
      "--chains", attackChainsPath,
      "--output", finalReportModelPath,
    ]);
    const policyFinalReportModelPath = join(coverage, "policy-final-report-model.json");
    const policyFinalReportPath = join(coverage, "security-audit-report-policy.fixture.md");
    run("build-final-report-model.mjs", [
      "--audit-id", AUDIT_ID,
      "--mode", "policy-final",
      "--coverage-summary", summaryPath,
      "--adjudication-input", adjudicationInputPath,
      "--adjudication", adjudicationPath,
      "--cvss", cvssAssessmentPath,
      "--chains", attackChainsPath,
      "--output", policyFinalReportModelPath,
    ]);
    run("render-final-report.mjs", ["--model", policyFinalReportModelPath, "--output", policyFinalReportPath]);
    run("verify-final-report.mjs", ["--model", policyFinalReportModelPath, "--markdown", policyFinalReportPath]);
    const policyFinalReportModel = JSON.parse(await readFile(policyFinalReportModelPath, "utf8"));
    if (policyFinalReportModel.report_kind !== "POLICY_FINAL" || !policyFinalReportModel.coverage.policy_satisfied) {
      throw new Error("Policy-final report did not preserve policy acceptance independently from report rendering");
    }
    run("build-final-report-model.mjs", [
      "--audit-id", AUDIT_ID,
      "--mode", "checkpoint",
      "--coverage-summary", summaryPath,
      "--adjudication-input", adjudicationInputPath,
      "--adjudication", adjudicationPath,
      "--cvss", cvssAssessmentPath,
      "--chains", attackChainsPath,
      "--output", join(coverage, "checkpoint-from-complete-model.json"),
    ], 1);
    run("render-final-report.mjs", ["--model", finalReportModelPath, "--output", finalReportPath]);
    run("verify-final-report.mjs", ["--model", finalReportModelPath, "--markdown", finalReportPath]);
    const finalReportModel = JSON.parse(await readFile(finalReportModelPath, "utf8"));
    const finalReport = await readFile(finalReportPath, "utf8");
    if (finalReportModel.findings.length !== 1 || finalReportModel.chains.length !== 1
      || finalReportModel.findings[0].attack_surface?.schema_version !== 1
      || !finalReportModel.findings[0].attack_surface_source?.json_pointer?.endsWith("/finding/attack_surface")
      || !finalReport.includes("## Per-Finding Attack Surface")
      || !finalReport.includes("fixture HTTP request parameter")
      || finalReport.includes("CONFIRMED") || !finalReport.includes("GENERATED: final-report-model")) {
      throw new Error("Final report model did not preserve only adjudicated, provenance-bound results");
    }
    await writeFile(finalReportPath, `${finalReport}\nCONFIRMED\n`, "utf8");
    run("verify-final-report.mjs", ["--model", finalReportModelPath, "--markdown", finalReportPath], 1);
    run("render-final-report.mjs", ["--model", finalReportModelPath, "--output", finalReportPath]);
    const conflictingOutputPath = join(coverage, "coverage-conflicting-output.json");
    run("verify-coverage-v3.mjs", [
      ...commonVerifyArgs,
      "--reports-dir", positiveReports,
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural-output", join(coverage, "coverage-conflicting-structural.json"),
      "--summary-output", conflictingOutputPath,
      "--markdown-output", conflictingOutputPath,
      "--output", join(coverage, "coverage-conflicting-verification.json"),
    ], 1);
    const findingArtifactBytes = await readFile(findingArtifactPath);
    await writeFile(findingArtifactPath, `${findingArtifactBytes.toString("utf8")}\nmodified-after-finalization\n`, "utf8");
    const modifiedFindingVerification = await verifyLedger({
      planPath: coveragePlanPath,
      ledgerPath,
      requireFinalized: true,
    });
    if (modifiedFindingVerification.complete
      || !modifiedFindingVerification.issues.some(issue => issue.code === "FINDING_ARTIFACT_INVALID")) {
      throw new Error("Post-finalization finding artifact drift was not detected");
    }
    await writeFile(findingArtifactPath, findingArtifactBytes);
    const tamperedSummaryPath = join(coverage, "coverage-summary-tampered.json");
    const tamperedSummary = JSON.parse(await readFile(summaryPath, "utf8"));
    tamperedSummary.accounting.known_coverage.percentage = 99.99;
    tamperedSummary.manifest_digest = objectDigest(tamperedSummary);
    await writeFile(tamperedSummaryPath, `${JSON.stringify(tamperedSummary, null, 2)}\n`, "utf8");
    run("verify-coverage-summary.mjs", [
      "--summary", tamperedSummaryPath,
      "--markdown", summaryMarkdownPath,
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural", v3StructuralOutput,
    ], 1);

    const tamperedLedgerPath = join(coverage, "coverage-ledger-tampered.jsonl");
    const ledgerLines = (await readFile(ledgerPath, "utf8")).trim().split("\n").map(JSON.parse);
    const receiptEvent = ledgerLines.find(event => event.event_type === "RECEIPT");
    receiptEvent.result_summary = "tampered after sealing";
    await writeFile(tamperedLedgerPath, `${ledgerLines.map(JSON.stringify).join("\n")}\n`, "utf8");
    await cp(`${ledgerPath}.key`, `${tamperedLedgerPath}.key`);
    await expectReject(() => verifyLedger({
      planPath: coveragePlanPath,
      ledgerPath: tamperedLedgerPath,
      requireFinalized: true,
    }), /Ledger hash mismatch/);
    const permissiveKeyLedgerPath = join(coverage, "coverage-ledger-permissive-key.jsonl");
    await cp(ledgerPath, permissiveKeyLedgerPath);
    await cp(`${ledgerPath}.key`, `${permissiveKeyLedgerPath}.key`);
    await chmod(`${permissiveKeyLedgerPath}.key`, 0o644);
    await expectReject(() => verifyLedger({
      planPath: coveragePlanPath,
      ledgerPath: permissiveKeyLedgerPath,
      requireFinalized: true,
    }), /key permissions must be 0600/);

    run("verify-coverage-v3.mjs", [
      ...commonVerifyArgs,
      "--reports-dir", positiveReports,
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural-output", join(coverage, "forged-structural-output.json"),
      "--summary-output", join(coverage, "forged-structural-summary.json"),
      "--markdown-output", join(coverage, "forged-structural-summary.md"),
      "--output", join(coverage, "forged-structural-verification.json"),
      "--structural", positiveOutput,
    ], 1);

    const zeroInterfaceManifestPath = join(coverage, "interface-manifest-zero-incomplete.json");
    const zeroInterfaceManifest = structuredClone(interfaceManifest);
    delete zeroInterfaceManifest.manifest_digest;
    zeroInterfaceManifest.interfaces = [];
    for (const row of zeroInterfaceManifest.file_coverage) row.interface_ids = [];
    const blockedRow = zeroInterfaceManifest.file_coverage[0];
    blockedRow.state = "INDETERMINATE";
    blockedRow.reason = "zero-interface-inventory-regression";
    blockedRow.gaps = [{ code: "INTERFACE_EXTRACTOR_INDETERMINATE", reason: blockedRow.reason }];
    zeroInterfaceManifest.gaps = [{
      file_id: blockedRow.file_id,
      path: blockedRow.path,
      code: "INTERFACE_EXTRACTOR_INDETERMINATE",
      reason: blockedRow.reason,
    }];
    zeroInterfaceManifest.summary = {
      ...zeroInterfaceManifest.summary,
      inspected_files: zeroInterfaceManifest.file_coverage.filter(row => row.state === "INSPECTED").length,
      not_applicable_files: zeroInterfaceManifest.file_coverage.filter(row => row.state === "NOT_APPLICABLE").length,
      indeterminate_files: 1,
      failed_files: 0,
      interfaces: 0,
      confirmed_interfaces: 0,
      candidate_interfaces: 0,
      rejected_interfaces: 0,
      ingress: 0,
      egress: 0,
      bidirectional: 0,
    };
    zeroInterfaceManifest.complete = false;
    zeroInterfaceManifest.inventory_bounded = false;
    zeroInterfaceManifest.manifest_digest = objectDigest(zeroInterfaceManifest);
    await writeFile(zeroInterfaceManifestPath, `${JSON.stringify(zeroInterfaceManifest, null, 2)}\n`, "utf8");
    const zeroInterfaceExtractorPath = join(coverage, "interface-extractors-zero-incomplete.json");
    run("verify-interface-extractors.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      "--interfaces", zeroInterfaceManifestPath,
      "--output", zeroInterfaceExtractorPath,
    ], 2);
    const blockedSnapshotDir = join(work, "durable-snapshot-zero-interface");
    run("snapshot-coverage-inputs.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", scopePath,
      ...functionPaths.flatMap(path => ["--functions", path]),
      "--interfaces", zeroInterfaceManifestPath,
      "--interface-extractors", zeroInterfaceExtractorPath,
      "--catalog", CATALOG,
      "--threat-model", threatModelPath,
      "--focus-areas", focusAreasPath,
      "--output-dir", blockedSnapshotDir,
    ]);
    const blockedSnapshotIndexPath = join(blockedSnapshotDir, "snapshot-index.json");
    const blockedSnapshot = JSON.parse(await readFile(blockedSnapshotIndexPath, "utf8"));
    const blockedPlanPath = join(coverage, "coverage-plan-zero-interface.json");
    run("build-coverage-plan.mjs", [
      "--audit-id", AUDIT_ID,
      "--coverage-mode", "assurance",
      "--scope", blockedSnapshot.scope.path,
      ...blockedSnapshot.functions.flatMap(item => ["--functions", item.path]),
      "--interfaces", blockedSnapshot.interfaces.path,
      "--interface-extractors", blockedSnapshot.interface_extractors.path,
      "--catalog", blockedSnapshot.catalog.path,
      "--focus-areas", blockedSnapshot.semantic.focus_areas.path,
      "--snapshot-index", blockedSnapshotIndexPath,
      "--output", blockedPlanPath,
    ]);
    const blockedPlan = JSON.parse(await readFile(blockedPlanPath, "utf8"));
    if (blockedPlan.complete || blockedPlan.universes.interfaces !== 0 || blockedPlan.inventory.gap_files !== 1
      || blockedPlan.inventory.bounded || blockedPlan.summary.unknown !== 0) {
      throw new Error("Zero-interface incomplete inventory was not represented as a non-atomic blocker");
    }
    const blockedLedgerPath = join(coverage, "coverage-ledger-zero-interface.jsonl");
    await initializeLedger({ planPath: blockedPlanPath, ledgerPath: blockedLedgerPath });
    await expectReject(() => finalizeLedger({
      planPath: blockedPlanPath,
      ledgerPath: blockedLedgerPath,
      idempotencyKey: "invalid-unbounded-finalize",
    }), /unbounded inventory/);
    await checkpointLedger({
      planPath: blockedPlanPath,
      ledgerPath: blockedLedgerPath,
      idempotencyKey: "zero-interface-partial-checkpoint",
      label: "zero-interface-blocked",
    });
    const blockedVerificationPath = join(coverage, "coverage-verification-zero-interface.json");
    const blockedStructuralPath = join(coverage, "coverage-structural-zero-interface.json");
    const blockedSummaryPath = join(coverage, "coverage-summary-zero-interface.json");
    const blockedMarkdownPath = join(coverage, "coverage-summary-zero-interface.md");
    run("verify-coverage-v3.mjs", [
      "--mode", "partial",
      "--root", root,
      "--audit-id", AUDIT_ID,
      "--scope", blockedSnapshot.scope.path,
      "--interfaces", blockedSnapshot.interfaces.path,
      "--interface-extractors", blockedSnapshot.interface_extractors.path,
      "--snapshot-index", blockedSnapshotIndexPath,
      ...blockedSnapshot.functions.flatMap(item => ["--functions", item.path]),
      "--reports-dir", positiveReports,
      "--catalog", blockedSnapshot.catalog.path,
      "--plan", blockedPlanPath,
      "--ledger", blockedLedgerPath,
      "--structural-output", blockedStructuralPath,
      "--summary-output", blockedSummaryPath,
      "--markdown-output", blockedMarkdownPath,
      "--output", blockedVerificationPath,
    ], 2);
    const blockedSummary = JSON.parse(await readFile(blockedSummaryPath, "utf8"));
    if (blockedSummary.coverage_status !== "BLOCKED"
      || blockedSummary.seal_state !== "PARTIAL_CHECKPOINT"
      || blockedSummary.accounting.conservative_lower_bound.state !== "UNBOUNDED"
      || blockedSummary.external_interfaces.state !== "BLOCKED"
      || blockedSummary.external_interfaces.conservative_lower_bound.state !== "UNBOUNDED"
      || blockedSummary.vulnerability_types.conservative_lower_bound.state === "UNBOUNDED") {
      throw new Error("Unbounded zero-interface inventory produced an optimistic coverage statistic");
    }
    const observedBlockedPlan = structuredClone(blockedPlan);
    observedBlockedPlan.coverage_policy.mode = "observe";
    observedBlockedPlan.manifest_digest = objectDigest(observedBlockedPlan);
    const observedBlockedPlanPath = join(coverage, "coverage-plan-zero-interface-observe.json");
    const observedBlockedLedgerPath = join(coverage, "coverage-ledger-zero-interface-observe.jsonl");
    await writeFile(observedBlockedPlanPath, `${JSON.stringify(observedBlockedPlan, null, 2)}\n`, "utf8");
    await initializeLedger({ planPath: observedBlockedPlanPath, ledgerPath: observedBlockedLedgerPath });
    await finalizeLedger({
      planPath: observedBlockedPlanPath,
      ledgerPath: observedBlockedLedgerPath,
      idempotencyKey: "observe-unbounded-finalize",
    });
    const observedBlockedReports = join(work, "reports-observe-unbounded");
    await cp(positiveReports, observedBlockedReports, { recursive: true });
    const observedBlockedFindingReportPath = join(
      observedBlockedReports,
      `${DOMAIN_AGENTS[firstRequiredCheck.domain]}.${firstRequiredCheck.lens}.audit-report.json`,
    );
    const observedBlockedFindingReport = JSON.parse(await readFile(observedBlockedFindingReportPath, "utf8"));
    const observedBlockedFindingRecord = observedBlockedFindingReport.catalog_coverage.find(record =>
      record.catalog_id === firstRequiredCheck.vulnerability_type_id && record.domain === firstRequiredCheck.domain);
    observedBlockedFindingRecord.status = "REVIEWED";
    observedBlockedFindingRecord.finding_ids = [];
    observedBlockedFindingReport.findings = [];
    await writeFile(observedBlockedFindingReportPath, `${JSON.stringify(observedBlockedFindingReport, null, 2)}\n`, "utf8");
    run("reconcile-audit-report.mjs", [
      "--report", observedBlockedFindingReportPath,
      "--scope", blockedSnapshot.scope.path,
      "--catalog", blockedSnapshot.catalog.path,
    ]);
    const observedBlockedVerificationPath = join(coverage, "coverage-verification-zero-interface-observe.json");
    run("verify-coverage-v3.mjs", [
      "--mode", "policy",
      "--root", root,
      "--audit-id", AUDIT_ID,
      "--scope", blockedSnapshot.scope.path,
      "--interfaces", blockedSnapshot.interfaces.path,
      "--interface-extractors", blockedSnapshot.interface_extractors.path,
      "--snapshot-index", blockedSnapshotIndexPath,
      ...blockedSnapshot.functions.flatMap(item => ["--functions", item.path]),
      "--reports-dir", observedBlockedReports,
      "--catalog", blockedSnapshot.catalog.path,
      "--plan", observedBlockedPlanPath,
      "--ledger", observedBlockedLedgerPath,
      "--structural-output", join(coverage, "coverage-structural-zero-interface-observe.json"),
      "--summary-output", join(coverage, "coverage-summary-zero-interface-observe.json"),
      "--markdown-output", join(coverage, "coverage-summary-zero-interface-observe.md"),
      "--output", observedBlockedVerificationPath,
    ]);
    const observedBlockedVerification = JSON.parse(await readFile(observedBlockedVerificationPath, "utf8"));
    if (!observedBlockedVerification.policy_satisfied || observedBlockedVerification.complete
      || observedBlockedVerification.coverage_status !== "BLOCKED"
      || observedBlockedVerification.seal_state !== "FINALIZED_OBSERVED") {
      throw new Error("Observe policy did not remain non-blocking for an explicitly unbounded inventory");
    }

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
    const negativeSummaryMarkdownPath = join(coverage, "coverage-summary-missing-function.md");
    run("render-coverage-summary.mjs", [
      "--plan", coveragePlanPath,
      "--ledger", ledgerPath,
      "--structural", negativeOutput,
      "--output", negativeSummaryPath,
      "--markdown-output", negativeSummaryMarkdownPath,
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

    const partialRoot = join(work, "fixture-partial-python");
    const partialCoverage = join(work, "coverage-partial-python");
    await mkdir(partialRoot, { recursive: true });
    await mkdir(partialCoverage, { recursive: true });
    await writeFile(join(partialRoot, "service.py"), "def handle(value):\n    return value\n", "utf8");
    const partialScopePath = join(partialCoverage, "scope.json");
    const partialCapabilitiesPath = join(partialCoverage, "parser-capabilities.json");
    const detectedCapabilitiesPath = join(partialCoverage, "parser-capabilities-detected.json");
    const partialInterfacesPath = join(partialCoverage, "interface-manifest.json");
    const partialExtractorsPath = join(partialCoverage, "interface-extractor-coverage.json");
    const partialRoutingPath = join(partialCoverage, "threat-routing-index.json");
    run("build-scope-manifest.mjs", ["--root", partialRoot, "--audit-id", AUDIT_ID, "--output", partialScopePath]);
    const partialScope = JSON.parse(await readFile(partialScopePath, "utf8"));
    run("build-parser-capabilities.mjs", ["--root", partialRoot, "--audit-id", AUDIT_ID, "--scope", partialScopePath, "--output", detectedCapabilitiesPath]);
    const detectedCapabilities = JSON.parse(await readFile(detectedCapabilitiesPath, "utf8"));
    if (!detectedCapabilities.capabilities.some(item => item.parser === "joern-python" && ["available", "unavailable"].includes(item.status))) {
      throw new Error("Parser capability probe did not emit a Python frontend status");
    }
    await writeParserCapabilities(partialCapabilitiesPath, partialScope, [{
      parser: "joern-python",
      status: "unavailable",
      reason: "fixture-python-frontend-unavailable",
      files: ["service.py"],
    }]);
    const partialBuild = JSON.parse(run("build-function-manifests.mjs", [
      "--root", partialRoot,
      "--audit-id", AUDIT_ID,
      "--scope", partialScopePath,
      "--parser-capabilities", partialCapabilitiesPath,
      "--allow-partial", "true",
      "--output-dir", partialCoverage,
      "--jobs", "2",
    ]).stdout);
    if (partialBuild.complete || !partialBuild.partial || !partialBuild.skipped.some(item => item.parser === "joern-python")) {
      throw new Error("Unavailable Python parser did not produce an explicit partial function-inventory result");
    }
    const partialFunctionPaths = ["java", "javascript", "embedded-web"].map(language => join(partialCoverage, `functions-${language}.json`));
    run("build-interface-manifest.mjs", ["--root", partialRoot, "--audit-id", AUDIT_ID, "--scope", partialScopePath, "--output", partialInterfacesPath]);
    run("verify-interface-extractors.mjs", ["--audit-id", AUDIT_ID, "--scope", partialScopePath, "--interfaces", partialInterfacesPath, "--output", partialExtractorsPath]);
    const partialRoutingArgs = [
      "--audit-id", AUDIT_ID,
      "--scope", partialScopePath,
      ...partialFunctionPaths.flatMap(path => ["--functions", path]),
      "--interfaces", partialInterfacesPath,
      "--interface-extractors", partialExtractorsPath,
      "--catalog", CATALOG,
      "--parser-capabilities", partialCapabilitiesPath,
      "--output", partialRoutingPath,
    ];
    run("build-threat-routing-index.mjs", partialRoutingArgs, 1);
    const partialRouting = JSON.parse(run("build-threat-routing-index.mjs", [...partialRoutingArgs, "--allow-partial", "true"]).stdout);
    const partialIndex = JSON.parse(await readFile(partialRoutingPath, "utf8"));
    if (partialRouting.complete || !partialRouting.partial || partialIndex.complete || partialIndex.gaps.length !== 1
      || partialIndex.gaps[0].path !== "service.py" || partialIndex.routes.find(route => route.path === "service.py")?.function_inventory.state !== "unavailable") {
      throw new Error("Partial threat-routing index did not preserve the Python parser gap");
    }
    run("snapshot-coverage-inputs.mjs", [
      "--audit-id", AUDIT_ID,
      "--scope", partialScopePath,
      ...partialFunctionPaths.flatMap(path => ["--functions", path]),
      "--interfaces", partialInterfacesPath,
      "--interface-extractors", partialExtractorsPath,
      "--catalog", CATALOG,
      "--output-dir", join(partialCoverage, "snapshot"),
    ], 1);

    process.stdout.write(`${JSON.stringify({ complete: true, positive: positive.expected, coverage_v3: { required_checks: coveragePlan.summary.required, not_applicable_checks: coveragePlan.summary.not_applicable, source_sets: coveragePlan.source_sets.length, focus_area_bound: true, snapshot_bound: true, legacy_v2_rejected: true, candidate_interfaces_non_atomic: true, artifact_bound_findings: 1, finalized_hash_chain: true, exact_summary: true }, git_aware_scope_pruning: true, function_manifest_resume_cache: true, cache_rejects_scope_drift: true, compact_threat_routing_index: true, parser_unavailable_partial_routing: true, partial_audit_snapshot_blocked: true, focus_catalog_assignment_preflight: true, isolated_joern_workspace: true, deterministic_interface_inventory: true, dynamic_interface_gap_caught: "static/dynamic-route.js", failed_interface_extractor_caught: true, tampered_interface_manifest_caught: true, machine_reconciled_coverage_cells: true, self_reported_target_counts_rejected: true, forged_evidence_rejected: true, stale_receipt_rejected: true, incomplete_source_universe_rejected: true, receiptless_verified_rejected: true, fake_check_id_rejected: true, two_lens_plan_rejected: true, agent_declared_na_rejected: true, tampered_summary_rejected: true, tampered_ledger_chain_rejected: true, ai_initializer_requires_surface_inventory: true, targeted_gap_round_preserved_prior_coverage: true, negative_missing_function_caught: removedFunction, containing_file_completeness_reduced: true, negative_missing_ai_overlay_file_caught: removedAiFile, missing_dimension_cell_caught: "D10", tampered_scope_caught: true, tampered_function_manifest_caught: true, unsupported_function_source_caught: "Unsupported.groovy", malformed_javascript_caught: "broken.js" })}\n`);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
