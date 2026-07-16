#!/usr/bin/env node

import { readFile, readdir, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");
const OPENCODE = join(ROOT, ".opencode");
const REQUIRED_LENSES = ["sink-driven", "control-driven", "config-driven"];
const REQUIRED_DIMENSIONS = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sameSet(left, right) {
  return left.length === right.length && new Set(left).size === left.length && left.every(value => right.includes(value));
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
  const config = await json(join(OPENCODE, "opencode.json"));
  const catalog = await json(join(OPENCODE, "shared/security-audit/catalogs/application-ai-vulnerability-catalog.json"));
  const orchestratorText = await readFile(join(OPENCODE, "agents/security-audit-orchestrator.md"), "utf8");

  const roleAgents = Object.keys(roles.agents).sort();
  const agentFiles = (await readdir(join(OPENCODE, "agents"))).filter(name => name.endsWith(".md")).map(name => name.slice(0, -3)).sort();
  assert(sameSet(roleAgents, agentFiles), `roles.json and agent Markdown files differ: roles=${roleAgents} files=${agentFiles}`);
  assert(roleAgents.includes(config.default_agent), "default_agent is not declared in roles.json");
  assert(roleAgents.includes("ai-security-auditor"), "AI security auditor is not registered");
  assert(roleAgents.includes("security-threat-modeler"), "Threat modeler is not registered");
  assert(roleAgents.includes("security-attack-chain-hunter"), "Attack-chain hunter is not registered");
  assert(sameSet(roleAgents, Object.keys(mcpMap.agents).sort()), "mcp-map agent keys do not equal role agent keys");
  assert(/^permission:\s*allow\s*$/m.test(orchestratorText), "security-audit-orchestrator must default to all permissions without approval");

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
      const skillText = await readFile(join(dirname(collectionPath), skill, "SKILL.md"), "utf8");
      const frontmatterName = /^---\s*$[\s\S]*?^name:\s*([^\s]+)\s*$/m.exec(skillText)?.[1];
      assert(frontmatterName === skill, `${collectionName}/${skill} frontmatter name mismatch`);
      skillCount += 1;
    }
  }

  const requiredAgents = artifactPolicy.reports.vulnerability_mining.required_for_agents;
  assert(requiredAgents.every(agent => roleAgents.includes(agent)), "artifact policy references an unknown vulnerability-mining agent");
  for (const field of ["round", "focus_area_id", "discovery_track", "coverage_cells", "review_depth", "file_coverage", "function_coverage", "catalog_coverage"]) {
    assert(artifactPolicy.reports.vulnerability_mining.required_fields.includes(field), `artifact policy lacks required field ${field}`);
  }
  assert(artifactPolicy.reports.vulnerability_mining.path_template.endsWith(".audit-report.json"), "audit report path is not verifier-discoverable");
  assert(artifactPolicy.reports.coverage_verification.required_fields.includes("claim_boundary"), "coverage verification policy lacks claim boundary");
  assert(artifactPolicy.reports.semantic_coverage_verification.required_fields.includes("claim_boundary"), "semantic coverage verification policy lacks claim boundary");
  assert(artifactPolicy.reports.hypothesis_discovery.required_fields.includes("seed_inputs"), "discovery policy lacks seed provenance");
  assert(artifactPolicy.reports.attack_chain.required_for_agents.includes("security-attack-chain-hunter"), "attack-chain report is not mandatory");
  assert(artifactPolicy.work.required_recon_files.includes("threat-model.json") && artifactPolicy.work.required_recon_files.includes("focus-areas.json"), "semantic Recon artifacts are not mandatory");
  for (const script of ["seal-semantic-manifest.mjs", "verify-semantic-coverage.mjs"]) {
    assert(await exists(join(OPENCODE, "skills/common-subagent/audit-coverage-accounting/scripts", script)), `semantic coverage script is missing: ${script}`);
  }

  assert(config.mcp.joern?.enabled === true, "local Joern MCP must be enabled");
  assert(sameSet(catalog.required_lenses, REQUIRED_LENSES), "catalog does not require the canonical three lenses");
  const catalogIds = catalog.entries.map(entry => entry.id);
  assert(new Set(catalogIds).size === catalogIds.length, "catalog IDs are not unique");
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

  process.stdout.write(`${JSON.stringify({ complete: true, agents: roleAgents.length, collections: actualCollections.length, skills: skillCount, semantic_agents: ["security-threat-modeler", "security-attack-chain-hunter"], semantic_verifier: true, catalog_entries: catalog.entries.length, ai_catalog_entries: aiEntries.length, owasp_ai_agent_controls: requiredAiAgentControls, catalog_dimensions: [...catalogDimensions].sort(), ai_catalog_dimensions: [...aiDimensions].sort() })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
