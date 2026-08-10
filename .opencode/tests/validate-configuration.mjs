#!/usr/bin/env node

import { readFile, readdir, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { validateStageContractRegistry } from "../skills/common-subagent/audit-artifact-management/scripts/stage-agent-contract.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");
const OPENCODE = join(ROOT, ".opencode");
const REQUIRED_LENSES = ["sink-driven", "control-driven", "config-driven"];
const REQUIRED_DIMENSIONS = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);
const REMOVED_MCP_PLACEHOLDERS = ["context7", "gh_grep", "codeql"];
const SEMGREP_AGENTS = [
  "c-cpp-source-auditor",
  "java-source-auditor",
  "web-source-auditor",
  "python-source-auditor",
  "platform-security-auditor",
  "ai-security-auditor",
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sameSet(left, right) {
  return left.length === right.length && new Set(left).size === left.length && left.every(value => right.includes(value));
}

function containsAction(value, action) {
  if (value === action) return true;
  if (!value || typeof value !== "object") return false;
  return Object.values(value).some(child => containsAction(child, action));
}

async function json(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function exists(path) {
  try { return (await stat(path)).isFile(); } catch { return false; }
}

async function main() {
  const manifestDir = join(OPENCODE, "agent-manifest");
  const roles = await json(join(manifestDir, "roles.json"));
  const skillMap = await json(join(manifestDir, "skill-map.json"));
  const mcpMap = await json(join(manifestDir, "mcp-map.json"));
  const artifactPolicy = await json(join(manifestDir, "artifact-policy.json"));
  const config = await json(join(OPENCODE, "opencode.json.bak"));
  const rootGitignore = await readFile(join(ROOT, ".gitignore"), "utf8");
  const catalog = await json(join(OPENCODE, "shared/security-audit/catalogs/application-ai-vulnerability-catalog.json"));
  const orchestratorText = await readFile(join(OPENCODE, "agents/security-audit-orchestrator.md"), "utf8");
  const validatorText = await readFile(join(OPENCODE, "agents/vulnerability-validator.md"), "utf8");
  const dynamicValidatorText = await readFile(join(OPENCODE, "agents/dynamic-vulnerability-validator.md"), "utf8");
  const rootAgentsText = await readFile(join(ROOT, "AGENTS.md"), "utf8");
  const joernManifestBuilderText = await readFile(join(OPENCODE, "skills/common-subagent/audit-coverage-accounting/scripts/build-joern-function-manifest.mjs"), "utf8");
  const parserCapabilitiesText = await readFile(join(OPENCODE, "skills/common-subagent/audit-coverage-accounting/scripts/build-parser-capabilities.mjs"), "utf8");
  const semgrepCliText = await readFile(join(OPENCODE, "scripts/semgrep-scan.mjs"), "utf8");
  const semgrepCoreText = await readFile(join(OPENCODE, "scripts/semgrep-core.mjs"), "utf8");
  const coverageServerText = await readFile(join(OPENCODE, "mcp/coverage-ledger-server.mjs"), "utf8");
  const coverageCoreText = await readFile(join(OPENCODE, "skills/common-subagent/audit-coverage-accounting/scripts/coverage-ledger-core.mjs"), "utf8");
  const packageConfig = await json(join(OPENCODE, "package.json"));
  const stageContractRegistry = await json(join(OPENCODE, "skills/common-subagent/audit-artifact-management/contracts/stage-agent-contracts.json"));

  const roleAgents = Object.keys(roles.agents).sort();
  const agentFiles = (await readdir(join(OPENCODE, "agents"))).filter(name => name.endsWith(".md")).map(name => name.slice(0, -3)).sort();
  assert(sameSet(roleAgents, agentFiles), `roles.json and agent Markdown files differ: roles=${roleAgents} files=${agentFiles}`);
  assert(roleAgents.includes(config.default_agent), "default_agent is not declared in roles.json");
  assert(rootGitignore.split(/\r?\n/).includes(".opencode/opencode.json"), "local .opencode/opencode.json must be ignored");
  assert(await exists(join(OPENCODE, "opencode.json.bak")), "portable OpenCode config template is missing");
  const templateText = JSON.stringify(config);
  for (const machinePath of ["/Users/", "/opt/homebrew/", "/usr/local/bin/joern", "\\\\Users\\\\"]) {
    assert(!templateText.includes(machinePath), `OpenCode config template contains a machine-specific path: ${machinePath}`);
    assert(!joernManifestBuilderText.includes(machinePath), `Joern manifest builder contains a machine-specific default path: ${machinePath}`);
    assert(!parserCapabilitiesText.includes(machinePath), `Parser capability builder contains a machine-specific default path: ${machinePath}`);
  }
  assert(!("joern" in config.mcp), "Joern must not be registered as a project MCP");
  assert(!("joern" in mcpMap.servers), "mcp-map must not register a Joern MCP");
  assert(!("joern_*" in config.permission), "global config must not retain Joern MCP permissions");
  assert(!await exists(join(OPENCODE, "mcp/joern-server.mjs")), "Joern MCP server must be removed");
  assert(!await exists(join(OPENCODE, "tests/run-joern-tests.mjs")), "Joern MCP integration test must be removed");
  assert(joernManifestBuilderText.includes('process.env.JOERN_BIN || "joern"')
    && joernManifestBuilderText.includes('process.env.JOERN_PARSE_BIN || "joern-parse"')
    && !joernManifestBuilderText.includes("mcp?.joern"), "Joern manifest builder must consume the direct CLI environment");
  assert(parserCapabilitiesText.includes('process.env.JOERN_PARSE_BIN || "joern-parse"')
    && !parserCapabilitiesText.includes("mcp?.joern"), "Parser capability builder must consume the direct Joern CLI environment");
  assert(await exists(join(ROOT, "docs/installation.md")), "initial installation guide is missing");
  assert(roleAgents.includes("ai-security-auditor"), "AI security auditor is not registered");
  assert(roleAgents.includes("security-threat-modeler"), "Threat modeler is not registered");
  assert(roleAgents.includes("security-attack-chain-hunter"), "Attack-chain hunter is not registered");
  assert(validateStageContractRegistry(stageContractRegistry, roles).length === 0, "stage/agent contract registry or role bindings are invalid");
  assert(stageContractRegistry.stages.length === 12
    && new Set(stageContractRegistry.contracts.map(contract => contract.agent_name)).size === roleAgents.length,
  "stage/agent contracts do not cover every phase and agent");
  assert(sameSet(roleAgents, Object.keys(mcpMap.agents).sort()), "mcp-map agent keys do not equal role agent keys");
  assert(/^\s*"\*": allow\s*$/m.test(orchestratorText), "security-audit-orchestrator must default to all permissions without approval");
  assert(/^\s*"coverage_\*": allow\s*$/m.test(orchestratorText), "security-audit-orchestrator must auto-allow Coverage Ledger MCP tools");
  assert(orchestratorText.includes('"*coverage-ledger.jsonl*": deny'), "security-audit-orchestrator must hard-deny direct canonical ledger writes");
  assert(config.permission["*"] === "allow", "global permission fallback must auto-approve otherwise unmatched operations");
  assert(!containsAction(config.permission, "ask"), "global permissions must not request user confirmation");
  assert(config.permission["vuln_judger_*"] === "deny", "global permission must deny vuln_judger MCP tools");
  assert(config.permission["vuln-judger_*"] === "deny", "global permission must deny vuln-judger MCP tools");
  assert(config.permission["coverage_*"] === "allow", "global permission must auto-allow Coverage Ledger MCP tools");
  assert(!("semgrep_*" in config.permission), "global config must not retain Semgrep/OpenGrep MCP permissions");
  for (const placeholder of REMOVED_MCP_PLACEHOLDERS) {
    assert(!(placeholder in config.mcp), `${placeholder} MCP placeholder must be absent from project config`);
    assert(!(placeholder in mcpMap.servers), `${placeholder} MCP placeholder must be absent from mcp-map`);
    assert(!(`${placeholder}_*` in config.permission), `${placeholder} tool permission must be absent from global config`);
  }
  for (const agentFile of agentFiles) {
    const agentText = await readFile(join(OPENCODE, "agents", `${agentFile}.md`), "utf8");
    const frontmatter = /^---\s*$([\s\S]*?)^---\s*$/m.exec(agentText)?.[1] ?? "";
    assert(!/:\s*ask\s*$/m.test(frontmatter), `${agentFile} permissions must not request user confirmation`);
    assert(!frontmatter.includes("joern_*"), `${agentFile} must not retain Joern MCP permissions`);
    assert(!frontmatter.includes("semgrep_*"), `${agentFile} must not retain Semgrep/OpenGrep MCP permissions`);
    for (const placeholder of REMOVED_MCP_PLACEHOLDERS) {
      assert(!frontmatter.includes(`${placeholder}_*`), `${agentFile} must not retain ${placeholder} placeholder permissions`);
    }
  }
  for (const [agent, toolPrefixes] of Object.entries(mcpMap.agents)) {
    assert(!toolPrefixes.includes("joern_*"), `${agent} must not retain Joern MCP routing`);
    assert(!toolPrefixes.includes("semgrep_*"), `${agent} must not retain Semgrep/OpenGrep MCP routing`);
    for (const placeholder of REMOVED_MCP_PLACEHOLDERS) {
      assert(!toolPrefixes.includes(`${placeholder}_*`), `${agent} must not retain ${placeholder} placeholder routing`);
    }
  }

  const collectionDirs = (await readdir(join(OPENCODE, "skills"), { withFileTypes: true }))
    .filter(entry => entry.isDirectory())
    .map(entry => entry.name);
  const actualCollections = [];
  for (const name of collectionDirs) if (await exists(join(OPENCODE, "skills", name, "collection.json"))) actualCollections.push(name);
  assert(sameSet(Object.keys(skillMap.collections).sort(), actualCollections.sort()), "skill-map collection keys do not equal collection.json directories");

  let skillCount = 0;
  for (const [collectionName, mapping] of Object.entries(skillMap.collections)) {
    const collectionPath = join(ROOT, mapping.directory, "collection.json");
    const collection = await json(collectionPath);
    assert(collection.owner_agent === mapping.owner_agent, `${collectionName} owner differs between skill-map and collection.json`);
    assert(collection.owner_agent === "shared" || roleAgents.includes(collection.owner_agent), `${collectionName} has unknown owner_agent`);
    const skillDirs = (await readdir(dirname(collectionPath), { withFileTypes: true }))
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name);
    const actualSkills = [];
    for (const name of skillDirs) if (await exists(join(dirname(collectionPath), name, "SKILL.md"))) actualSkills.push(name);
    assert(sameSet(collection.skills.slice().sort(), actualSkills.sort()), `${collectionName} collection skill list differs from SKILL.md directories`);
    for (const skill of collection.skills) {
      const skillDirectory = join(dirname(collectionPath), skill);
      const skillText = await readFile(join(skillDirectory, "SKILL.md"), "utf8");
      const frontmatterName = /^---\s*$[\s\S]*?^name:\s*([^\s]+)\s*$/m.exec(skillText)?.[1];
      assert(frontmatterName === skill, `${collectionName}/${skill} frontmatter name mismatch`);
      assert(!/\bcodeql\b/i.test(skillText), `${collectionName}/${skill} must not advertise the removed CodeQL execution path`);
      const manifestPath = join(skillDirectory, "manifest.yaml");
      if (await exists(manifestPath)) {
        const manifestText = await readFile(manifestPath, "utf8");
        assert(!/\bcodeql\b/i.test(manifestText), `${collectionName}/${skill} manifest must not advertise the removed CodeQL execution path`);
        let manifest;
        try {
          manifest = parseYaml(manifestText);
        } catch (error) {
          throw new Error(`${collectionName}/${skill} manifest.yaml is invalid: ${error.message}`);
        }
        const semgrepRules = manifest?.components?.rules?.semgrep;
        if (collectionName === "java-subagent") {
          assert(Array.isArray(semgrepRules) && semgrepRules.length > 0, `${collectionName}/${skill} must declare Semgrep-compatible rules`);
          for (const ruleName of semgrepRules) {
            const rulePath = join(skillDirectory, "rules", "semgrep", ruleName);
            assert(await exists(rulePath), `${collectionName}/${skill} references a missing Semgrep rule: ${ruleName}`);
            let ruleDocument;
            try {
              ruleDocument = parseYaml(await readFile(rulePath, "utf8"));
            } catch (error) {
              throw new Error(`${collectionName}/${skill}/${ruleName} is invalid YAML: ${error.message}`);
            }
            assert(Array.isArray(ruleDocument?.rules) && ruleDocument.rules.length > 0, `${collectionName}/${skill}/${ruleName} lacks a non-empty rules array`);
          }
        }
      }
      skillCount += 1;
    }
  }

  const requiredAgents = artifactPolicy.reports.vulnerability_mining.required_for_agents;
  assert(requiredAgents.every(agent => roleAgents.includes(agent)), "artifact policy references an unknown vulnerability-mining agent");
  for (const field of ["round", "finding_schema_version", "focus_area_id", "discovery_track", "coverage_cells", "review_depth", "file_coverage", "function_coverage", "catalog_coverage"]) {
    assert(artifactPolicy.reports.vulnerability_mining.required_fields.includes(field), `artifact policy lacks required field ${field}`);
  }
  assert(artifactPolicy.reports.vulnerability_mining.path_template.endsWith(".audit-report.json"), "audit report path is not verifier-discoverable");
  assert(artifactPolicy.reports.coverage_verification.required_fields.includes("claim_boundary"), "coverage verification policy lacks claim boundary");
  assert(artifactPolicy.reports.coverage_verification.required_fields.includes("summary")
    && artifactPolicy.reports.coverage_verification.required_fields.includes("seal_state"), "coverage v3 verification policy lacks sealed machine-derived summary");
  assert(artifactPolicy.reports.coverage_plan.required_fields.includes("checks")
    && artifactPolicy.reports.coverage_plan.required_fields.includes("source_sets")
    && artifactPolicy.reports.coverage_plan.required_fields.includes("inventory")
    && artifactPolicy.reports.coverage_plan.required_fields.includes("coverage_units")
    && artifactPolicy.reports.coverage_plan.required_fields.includes("coverage_policy"), "coverage plan policy lacks unit/atomic/source/inventory accounting");
  assert(artifactPolicy.reports.coverage_summary.required_fields.includes("manifest_digest")
    && artifactPolicy.reports.coverage_summary.required_fields.includes("coverage_status")
    && artifactPolicy.reports.coverage_summary.required_fields.includes("policy_satisfied")
    && artifactPolicy.reports.coverage_summary.required_fields.includes("execution")
    && artifactPolicy.reports.coverage_summary.required_fields.includes("inventory")
    && artifactPolicy.reports.coverage_summary.markdown_companion, "coverage summary policy lacks v3 digest/status/inventory/Markdown contract");
  assert(artifactPolicy.reports.coverage_ledger.optional_event_types.includes("UNIT_ATTESTATION")
    && artifactPolicy.reports.coverage_ledger.optional_event_types.includes("FINALIZE_OBSERVED")
    && artifactPolicy.reports.coverage_ledger.optional_event_types.includes("FINALIZE_RELEASE")
    && artifactPolicy.reports.coverage_ledger.optional_event_types.includes("FINALIZE_COMPLETE")
    && artifactPolicy.reports.coverage_ledger.optional_event_types.includes("PARTIAL_CHECKPOINT"), "coverage ledger policy lacks unit and policy seal events");
  assert(artifactPolicy.reports.semantic_coverage_verification.required_fields.includes("claim_boundary"), "semantic coverage verification policy lacks claim boundary");
  assert(artifactPolicy.reports.hypothesis_discovery.required_fields.includes("seed_inputs"), "discovery policy lacks seed provenance");
  assert(artifactPolicy.reports.stage_handoff?.registry?.endsWith("stage-agent-contracts.json")
    && artifactPolicy.reports.stage_handoff?.path_templates?.some(path => path.includes("stage-handoff-verification")),
  "stage handoff artifact policy is incomplete");
  assert(artifactPolicy.reports.external_runtime_validation_handoff?.required_request_fields?.includes("attack_surface")
    && artifactPolicy.reports.external_runtime_validation_handoff?.required_result_fields?.includes("safety_attestation")
    && artifactPolicy.reports.external_runtime_validation_handoff?.web_xss_extension_v2_required_fields?.includes("network_trace"),
  "external runtime-validation handoff policy is incomplete");
  assert(artifactPolicy.reports.audit_workbench_runtime?.path_templates?.includes("reports/platform/audit-runs/{audit_id}/events.jsonl")
    && artifactPolicy.reports.audit_workbench_runtime?.path_templates?.includes("reports/platform/dynamic-validation-runs/{validation_run_hash}/run.json")
    && artifactPolicy.reports.audit_workbench_runtime?.required_state_fields?.includes("event_sequence"),
  "audit workbench runtime artifact policy is incomplete");
  assert(artifactPolicy.reports.attack_chain.required_for_agents.includes("security-attack-chain-hunter")
    && artifactPolicy.reports.attack_chain.required_fields.includes("adjudication_manifest_digest")
    && artifactPolicy.reports.attack_chain.required_fields.includes("chain_accounting"), "attack-chain report contract is incomplete");
  assert(roleAgents.includes("security-finding-adjudicator"), "finding adjudicator is not registered");
  assert(roleAgents.includes("dynamic-vulnerability-validator"), "dynamic vulnerability validator is not registered");
  assert(artifactPolicy.reports.finding_adjudication?.required_fields.includes("input_manifest_digest")
    && artifactPolicy.reports.finding_adjudication?.required_fields.includes("decisions"), "finding adjudication artifact contract is incomplete");
  assert(await exists(join(OPENCODE, "tests/run-adjudication-regression-tests.mjs"))
    && packageConfig.scripts["test:adjudication-regressions"]?.includes("run-adjudication-regression-tests.mjs"), "Mall semantic twin regression suite is not enabled");
  assert(await exists(join(OPENCODE, "tests/run-semantic-reseed-tests.mjs"))
    && packageConfig.scripts["test:semantic-reseed"]?.includes("run-semantic-reseed-tests.mjs"), "source-equivalent semantic reseed regression suite is not enabled");
  assert(await exists(join(OPENCODE, "tests/run-cvss-assessment-tests.mjs"))
    && packageConfig.scripts["test:cvss-assessment"]?.includes("run-cvss-assessment-tests.mjs"), "CVSS assessment regression suite is not enabled");
  assert(await exists(join(OPENCODE, "tests/run-stage-agent-contract-tests.mjs"))
    && packageConfig.scripts["test:stage-agent-contract"]?.includes("run-stage-agent-contract-tests.mjs"),
  "stage/agent contract regression suite is not enabled");
  assert(await exists(join(OPENCODE, "tests/run-threat-model-contract-tests.mjs"))
    && packageConfig.scripts["test:threat-model-contract"]?.includes("run-threat-model-contract-tests.mjs"),
  "rich threat-model contract regression suite is not enabled");
  assert(await exists(join(OPENCODE, "tests/run-external-runtime-validation-contract-tests.mjs"))
    && packageConfig.scripts["test:external-runtime-validation-contract"]?.includes("run-external-runtime-validation-contract-tests.mjs"),
  "external runtime-validation handoff regression suite is not enabled");
  assert(await exists(join(OPENCODE, "tests/run-dynamic-validation-contract-tests.mjs"))
    && packageConfig.scripts["test:dynamic-validation-contract"]?.includes("run-dynamic-validation-contract-tests.mjs"),
  "dynamic runtime-validation regression suite is not enabled");
  assert(await exists(join(OPENCODE, "tests/run-dynamic-validation-observatory-tests.mjs"))
    && await exists(join(OPENCODE, "web/dynamic-validation-observatory/server.mjs"))
    && packageConfig.scripts["test:dynamic-validation-web"]?.includes("run-dynamic-validation-observatory-tests.mjs")
    && packageConfig.scripts["start:dynamic-validation-web"]?.includes("dynamic-validation-observatory/server.mjs"),
  "dynamic validation observatory is not enabled");
  assert(await exists(join(OPENCODE, "tests/run-audit-workbench-tests.mjs"))
    && await exists(join(OPENCODE, "web/dynamic-validation-observatory/audit-runner.mjs"))
    && await exists(join(OPENCODE, "web/dynamic-validation-observatory/validation-runner.mjs"))
    && await exists(join(OPENCODE, "web/dynamic-validation-observatory/workspace-model.mjs"))
    && packageConfig.scripts["test:audit-workbench"]?.includes("run-audit-workbench-tests.mjs")
    && packageConfig.scripts["start:audit-workbench"]?.includes("dynamic-validation-observatory/server.mjs"),
  "OpenCode audit workbench is not enabled");
  assert(artifactPolicy.reports.final_report?.model_path_template?.endsWith(".json")
    && artifactPolicy.reports.final_report?.model_required_fields?.includes("manifest_digest"), "final report policy lacks its deterministic report model");
  const thirdPartyReview = artifactPolicy.reports.third_party_review;
  assert(thirdPartyReview?.required_invocation?.tool === "vuln_judger_judge_report", "third-party review must use vuln_judger_judge_report");
  assert(Array.isArray(thirdPartyReview?.required_invocation?.tool_aliases) && thirdPartyReview.required_invocation.tool_aliases.includes("vuln-judger_judge_report"), "third-party review must alias vuln-judger_judge_report");
  assert(thirdPartyReview.required_invocation.engine === "opencode", "third-party review must force the OpenCode engine");
  assert(thirdPartyReview.required_invocation.wait_for_completion === false, "third-party review must start asynchronously");
  assert(thirdPartyReview.path_templates.every(path => path.startsWith("reports/validation/")), "third-party review artifacts must be durable reports/validation companions");
  assert(artifactPolicy.work.required_recon_files.includes("threat-model.json") && artifactPolicy.work.required_recon_files.includes("focus-areas.json"), "semantic Recon artifacts are not mandatory");
  for (const script of ["build-function-manifests.mjs", "build-interface-manifest.mjs", "build-source-anchored-interface-decisions.mjs", "resolve-interface-candidates.mjs", "verify-interface-extractors.mjs", "build-threat-routing-index.mjs", "validate-vulnerability-catalog-v2.mjs", "build-coverage-plan.mjs", "initialize-coverage-ledger.mjs", "checkpoint-coverage-ledger.mjs", "finalize-partial-coverage-ledger.mjs", "verify-coverage-v2.mjs", "verify-coverage-v3-core.mjs", "verify-coverage-v3.mjs", "render-coverage-summary.mjs", "verify-coverage-summary.mjs", "reconcile-audit-report.mjs", "seal-semantic-manifest.mjs", "reseed-semantic-manifests.mjs", "verify-semantic-coverage.mjs", "final-report-model-core.mjs", "build-final-report-model.mjs", "render-final-report.mjs", "verify-final-report.mjs"]) {
    assert(await exists(join(OPENCODE, "skills/common-subagent/audit-coverage-accounting/scripts", script)), `semantic coverage script is missing: ${script}`);
  }
  for (const script of ["stage-agent-contract.mjs", "seal-stage-agent-envelope.mjs", "validate-stage-agent-envelope.mjs", "verify-stage-agent-handoffs.mjs"]) {
    assert(await exists(join(OPENCODE, "skills/common-subagent/audit-artifact-management/scripts", script)), `stage/agent contract script is missing: ${script}`);
  }
  assert(await exists(join(OPENCODE, "skills/threat-modeling-subagent/evidence-backed-threat-modeling/scripts/threat-model-contract.mjs")),
    "rich threat-model contract script is missing");
  for (const script of ["external-runtime-validation-contract.mjs", "build-external-runtime-validation-request.mjs", "validate-external-runtime-validation-packet.mjs"]) {
    assert(await exists(join(OPENCODE, "skills/common-subagent/finding-evidence-contract/scripts", script)),
      `external runtime-validation handoff script is missing: ${script}`);
  }
  for (const script of ["cvss-assessment-contract.mjs", "build-cvss-assessment.mjs", "build-empty-cvss-assessment.mjs", "validate-cvss-assessment.mjs", "build-empty-finding-adjudication.mjs"]) {
    assert(await exists(join(OPENCODE, "skills/common-subagent/finding-adjudication/scripts", script)), `CVSS assessment script is missing: ${script}`);
  }
  assert(await exists(join(OPENCODE, "skills/attack-chain-subagent/system-attack-chain-hunting/scripts/build-empty-attack-chain-report.mjs")), "empty attack-chain report builder is missing");
  assert(artifactPolicy.work.required_recon_files.includes("coverage/threat-routing-index.json"), "compact threat-routing index is not mandatory");
  assert(artifactPolicy.work.required_recon_files.includes("coverage/interface-manifest.json")
    && artifactPolicy.work.required_recon_files.includes("coverage/interface-extractor-coverage.json"), "deterministic external-interface artifacts are not mandatory");

  assert(!("semgrep" in config.mcp), "Semgrep/OpenGrep must not be registered as a project MCP");
  assert(!("semgrep" in mcpMap.servers), "mcp-map must not register a Semgrep/OpenGrep MCP");
  assert(!await exists(join(OPENCODE, "mcp/semgrep-core.mjs"))
    && !await exists(join(OPENCODE, "mcp/semgrep-server.mjs")), "Semgrep/OpenGrep MCP files must be removed");
  assert(await exists(join(OPENCODE, "scripts/semgrep-core.mjs"))
    && await exists(join(OPENCODE, "scripts/semgrep-scan.mjs"))
    && await exists(join(OPENCODE, "tests/run-semgrep-tests.mjs")), "direct Semgrep/OpenGrep CLI implementation or tests are missing");
  assert(semgrepCliText.includes("MAX_OUTPUT_BYTES = 16 * 1024")
    && semgrepCoreText.includes("MAX_STDOUT_BYTES = 64 * 1024 * 1024")
    && semgrepCoreText.includes("stderrPath"), "direct Semgrep/OpenGrep CLI must bound context output and retain scanner stderr");
  for (const agent of SEMGREP_AGENTS) {
    const text = await readFile(join(OPENCODE, "agents", `${agent}.md`), "utf8");
    assert(text.includes("node .opencode/scripts/semgrep-scan.mjs health"), `${agent} must use the direct Semgrep/OpenGrep CLI`);
  }
  assert(config.mcp.coverage_ledger?.enabled === true && config.mcp.coverage_ledger.command?.includes(".opencode/mcp/coverage-ledger-server.mjs"), "local Coverage Ledger MCP must be enabled");
  assert(mcpMap.servers.coverage_ledger?.status === "enabled-local", "mcp-map must register Coverage Ledger as enabled-local");
  assert(coverageServerText.includes("MAX_RESPONSE_BYTES = 16 * 1024")
    && coverageServerText.includes('source_scope: z.literal("required")')
    && coverageServerText.includes("compactReceipt"), "Coverage Ledger MCP must enforce bounded responses and compact required-source-set receipts");
  assert(coverageCoreText.includes('"required-source-set"')
    && coverageCoreText.includes("source_set_sha256"), "Coverage Ledger core must bind frozen source universes by a server-derived digest");
  assert(await exists(join(OPENCODE, "tests/run-coverage-response-tests.mjs"))
    && packageConfig.scripts["test:coverage"]?.includes("run-coverage-response-tests.mjs"), "Coverage Ledger large-response regression test must be enabled");
  for (const agent of requiredAgents) {
    const text = await readFile(join(OPENCODE, "agents", `${agent}.md`), "utf8");
    assert(text.includes('source_scope: "required"'), `${agent} must use compact required-source-set receipts`);
  }
  for (const agent of [...requiredAgents, "security-evidence-correlator", "security-audit-orchestrator"]) {
    assert(mcpMap.agents[agent].includes("coverage_*"), `${agent} must receive Coverage Ledger tools`);
    const text = await readFile(join(OPENCODE, "agents", `${agent}.md`), "utf8");
    assert(/^\s*"coverage_\*": allow\s*$/m.test(text), `${agent} must auto-allow Coverage Ledger tools`);
    assert(text.includes('"*coverage-ledger.jsonl*": deny'), `${agent} must hard-deny direct ledger bash writes`);
  }
  assert(!("vuln_judger" in config.mcp), "project config must not shadow the globally configured vuln_judger server");
  assert(!("vuln-judger" in config.mcp), "project config must not shadow the globally configured vuln-judger alias");
  assert(mcpMap.servers.vuln_judger?.status === "global-config", "mcp-map must identify vuln_judger as supplied by global config");
  const chromeMcp = config.mcp["chrome-devtools"];
  assert(chromeMcp?.enabled === true && chromeMcp.type === "local", "Chrome DevTools MCP must be enabled locally");
  assert(sameSet(chromeMcp.command, ["npx", "-y", "chrome-devtools-mcp@latest", "--isolated=true", "--redact-network-headers=true", "--no-usage-statistics", "--no-performance-crux"]),
    "Chrome DevTools MCP command must use latest, isolation, redaction, and visible Chrome defaults");
  assert(!chromeMcp.command.some(argument => /headless|agent-browser|browser-url|ws-endpoint|auto-?connect|user-data-dir/i.test(argument)),
    "Chrome DevTools MCP must not use headless, agent-browser, an existing browser endpoint, or a persistent profile");
  assert(config.permission["chrome-devtools_*"] === "deny", "global permissions must deny Chrome DevTools tools");
  assert(mcpMap.servers["chrome-devtools"]?.status === "enabled-local", "mcp-map must register Chrome DevTools MCP");
  assert(sameSet(mcpMap.agents["dynamic-vulnerability-validator"], ["chrome-devtools_*"]), "dynamic validator must receive only Chrome DevTools MCP tools");
  assert(/^\s*"chrome-devtools_\*": allow\s*$/m.test(dynamicValidatorText), "dynamic validator must allow Chrome DevTools MCP tools");
  assert(dynamicValidatorText.includes("DOM_PROBE_ONLY") && dynamicValidatorText.includes("STORED_CROSS_USER"), "dynamic validator must enforce XSS evidence levels");
  assert(rootAgentsText.includes("Never reset browser state by killing Chrome")
    && rootAgentsText.includes("stored XSS")
    && rootAgentsText.includes("localhost"), "root AGENTS.md lacks dynamic-validation safety boundaries");
  assert(!("vuln-judger" in mcpMap.servers), "mcp-map must not retain a separate vuln-judger placeholder");
  assert(Array.isArray(mcpMap.servers.vuln_judger?.aliases) && mcpMap.servers.vuln_judger.aliases.includes("vuln-judger"), "vuln_judger must declare vuln-judger alias");
  assert(sameSet(mcpMap.agents["vulnerability-validator"], ["vuln_judger_*", "vuln-judger_*"]), "vulnerability-validator must receive both vuln_judger and vuln-judger MCP tool prefixes");
  assert(/^\s*"vuln_judger_\*": allow\s*$/m.test(validatorText), "vulnerability-validator must allow vuln_judger MCP tools");
  assert(/^\s*"vuln-judger_\*": allow\s*$/m.test(validatorText), "vulnerability-validator must allow vuln-judger MCP tools");
  assert((validatorText.includes("vuln_judger_judge_report") || validatorText.includes("vuln-judger_judge_report")) && validatorText.includes("engine: opencode"), "validator must submit the final report through the OpenCode vuln_judger/vuln-judger pipeline");
  assert(validatorText.includes("exactly once") && validatorText.includes("final comprehensive"), "validator must enforce one full-report submission");
  assert(orchestratorText.indexOf("build-final-report-model.mjs") < orchestratorText.indexOf("Invoke `vulnerability-validator` once")
    && orchestratorText.includes("verify-final-report.mjs"), "orchestrator must deterministically build and verify the final report before invoking vulnerability-validator");
  assert(sameSet(catalog.required_lenses, REQUIRED_LENSES), "catalog does not require the canonical three lenses");
  assert(catalog.schema_version === 2 && catalog.profile_id.endsWith("-v4"), "catalog v2 profile is not active");
  assert(sameSet(catalog.coverage_model.applicability_states, ["REQUIRED", "NOT_APPLICABLE", "UNKNOWN"]), "catalog applicability states are invalid");
  assert(sameSet(Object.keys(catalog.coverage_model.domain_profiles).sort(), ["ai", "c-cpp", "java", "platform", "python", "web"]), "catalog domain profiles are incomplete");
  const catalogIds = catalog.entries.map(entry => entry.id);
  assert(new Set(catalogIds).size === catalogIds.length, "catalog IDs are not unique");
  const parentChildEntry = catalog.entries.find(entry => entry.id === "JW-ACCESS-05");
  assert(parentChildEntry?.title === "Parent-child resource authorization binding", "parent-child resource authorization catalog entry is missing");
  assert(parentChildEntry.dimensions.includes("D3") && parentChildEntry.applies_to.includes("java") && parentChildEntry.applies_to.includes("web"), "parent-child resource authorization entry has incomplete D3 coverage");
  const aiParentChildEntry = catalog.entries.find(entry => entry.id === "AI-ACCESS-01");
  assert(aiParentChildEntry?.title === "Agent parent-child resource authorization binding" && aiParentChildEntry.applies_to.length === 1 && aiParentChildEntry.applies_to[0] === "ai", "AI parent-child resource authorization catalog entry is missing");
  const catalogDimensions = new Set(catalog.entries.flatMap(entry => entry.dimensions));
  assert(REQUIRED_DIMENSIONS.every(dimension => catalogDimensions.has(dimension)), "catalog does not cover every D1-D10 dimension");
  for (const entry of catalog.entries) {
    assert(entry.applies_to.length > 0 && entry.applies_to.every(domain => ["java", "web", "platform", "ai"].includes(domain)), `${entry.id} has invalid applies_to`);
    assert(entry.dimensions.length > 0 && entry.dimensions.every(dimension => REQUIRED_DIMENSIONS.includes(dimension)), `${entry.id} has invalid dimensions`);
    for (const lens of ["sink", "control", "config"]) assert(typeof entry[`${lens}_question`] === "string" && entry[`${lens}_question`].length >= 12, `${entry.id} lacks ${lens}_question`);
  }
  const aiEntries = catalog.entries.filter(entry => entry.applies_to.includes("ai"));
  const aiDimensions = new Set(aiEntries.flatMap(entry => entry.dimensions));
  const requiredAiAgentControls = ["AI-APPROVAL-01", "AI-MULTIAGENT-01", "AI-CONSOLE-01", "AI-TEST-01"];
  assert(aiEntries.length >= 15, "AI vulnerability catalog is too narrow");
  assert(aiEntries.every(entry => entry.id.startsWith("AI-")), "AI catalog entry lacks AI-prefixed ID");
  assert(REQUIRED_DIMENSIONS.every(dimension => aiDimensions.has(dimension)), "AI catalog does not cover every D1-D10 dimension");
  assert(requiredAiAgentControls.every(id => aiEntries.some(entry => entry.id === id)), "OWASP AI Agent control catalog entries are incomplete");
  assert(catalog.sources.includes("https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html"), "OWASP AI Agent Security Cheat Sheet source is missing");
  assert(artifactPolicy.reports.vulnerability_mining.required_for_agents.includes("ai-security-auditor"), "AI auditor report is not mandatory");
  assert(artifactPolicy.work.required_recon_files.includes("ai-surfaces.json"), "Recon policy does not require ai-surfaces.json");

  process.stdout.write(`${JSON.stringify({ complete: true, agents: roleAgents.length, collections: actualCollections.length, skills: skillCount, semantic_agents: ["security-threat-modeler", "security-attack-chain-hunter"], semantic_verifier: true, third_party_review: { server: "vuln_judger", engine: "opencode", input: "sealed-final-report", asynchronous: true }, catalog_entries: catalog.entries.length, ai_catalog_entries: aiEntries.length, owasp_ai_agent_controls: requiredAiAgentControls, catalog_dimensions: [...catalogDimensions].sort(), ai_catalog_dimensions: [...aiDimensions].sort() })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
