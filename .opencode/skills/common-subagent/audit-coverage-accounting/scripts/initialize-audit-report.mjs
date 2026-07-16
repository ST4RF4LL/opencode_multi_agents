#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const LENSES = ["sink-driven", "control-driven", "config-driven"];
const DIMENSIONS = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);
const DOMAIN_AGENT = new Map([
  ["java", "java-source-auditor"],
  ["web", "web-source-auditor"],
  ["platform", "platform-security-auditor"],
  ["ai", "ai-security-auditor"],
]);
const AGENT_LANGUAGE = new Map([
  ["c-cpp-source-auditor", "c-cpp"],
  ["java-source-auditor", "java"],
  ["web-source-auditor", "web"],
  ["python-source-auditor", "python"],
  ["platform-security-auditor", "platform"],
  ["ai-security-auditor", "ai"],
]);
const AI_AGENT = DOMAIN_AGENT.get("ai");

function parseArgs(argv) {
  const args = { functions: [], "file-id": [], "function-id": [], "catalog-id": [] };
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    const key = token.slice(2);
    if (["functions", "file-id", "function-id", "catalog-id"].includes(key)) args[key].push(value);
    else args[key] = value;
  }
  for (const key of ["audit-id", "round", "agent", "session", "lens", "language", "scope", "catalog", "threat-model", "focus-areas", "focus-area", "output"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  }
  args.round = Number(args.round);
  if (!Number.isInteger(args.round) || args.round < 1) throw new Error("--round must be a positive integer");
  if (!LENSES.includes(args.lens)) throw new Error(`Unsupported --lens: ${args.lens}`);
  if (!AGENT_LANGUAGE.has(args.agent) || AGENT_LANGUAGE.get(args.agent) !== args.language) throw new Error(`--agent and --language mismatch: ${args.agent}/${args.language}`);
  if (args.agent === AI_AGENT && !args["ai-surfaces"]) throw new Error("--ai-surfaces is required for ai-security-auditor");
  return args;
}

function selectAssignment(allItems, requestedIds, idField, label) {
  if (requestedIds === null) return allItems;
  if (new Set(requestedIds).size !== requestedIds.length) throw new Error(`Duplicate --${label} assignment`);
  const byId = new Map(allItems.map(item => [item[idField], item]));
  const unknown = requestedIds.filter(id => !byId.has(id));
  if (unknown.length > 0) throw new Error(`Unknown or unowned --${label}: ${unknown.join(", ")}`);
  return requestedIds.map(id => byId.get(id));
}

function gapRecord(idField, id, dimensions, evidence, reason) {
  return {
    [idField]: id,
    status: "GAP",
    dimensions_reviewed: dimensions,
    evidence: [evidence],
    gap_reason: reason,
  };
}

function contentDigest(value) {
  const copy = { ...value };
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const scopePath = resolve(args.scope);
  const catalogPath = resolve(args.catalog);
  const outputPath = resolve(args.output);
  const scope = JSON.parse(await readFile(scopePath, "utf8"));
  const catalog = JSON.parse(await readFile(catalogPath, "utf8"));
  if (scope.audit_id !== args["audit-id"] || !scope.complete || scope.manifest_digest !== contentDigest(scope)) throw new Error("Scope manifest is incomplete, modified, or bound to another audit");
  if (scope.files.some(file => file.function_inventory_state === "unsupported")) throw new Error("Scope contains unsupported potential function sources; add an extractor before initializing closable reports");

  const threatModelPath = resolve(args["threat-model"]);
  const focusAreasPath = resolve(args["focus-areas"]);
  const threatModel = JSON.parse(await readFile(threatModelPath, "utf8"));
  const focusManifest = JSON.parse(await readFile(focusAreasPath, "utf8"));
  if (threatModel.audit_id !== args["audit-id"] || threatModel.scope_digest !== scope.scope_digest || threatModel.manifest_digest !== contentDigest(threatModel)) {
    throw new Error("Threat model is incomplete, modified, or scope-mismatched");
  }
  if (focusManifest.audit_id !== args["audit-id"] || focusManifest.scope_digest !== scope.scope_digest || focusManifest.manifest_digest !== contentDigest(focusManifest)
    || focusManifest.threat_model_digest !== threatModel.manifest_digest || !LENSES.every(lens => focusManifest.required_lenses?.includes(lens))) {
    throw new Error("Focus Area manifest is incomplete, modified, or threat-model-mismatched");
  }
  const focusArea = focusManifest.focus_areas?.find(item => item.focus_area_id === args["focus-area"]);
  if (!focusArea) throw new Error(`Unknown --focus-area: ${args["focus-area"]}`);

  const functions = [];
  const manifestPaths = [];
  const membership = new Map();
  for (const input of args.functions) {
    const path = resolve(input);
    const manifest = JSON.parse(await readFile(path, "utf8"));
    manifestPaths.push(path);
    if (manifest.audit_id !== args["audit-id"] || manifest.scope_digest !== scope.scope_digest || !manifest.complete || manifest.manifest_digest !== contentDigest(manifest)) {
      throw new Error(`Function manifest is incomplete or scope-mismatched: ${path}`);
    }
    for (const file of manifest.expected_files ?? []) membership.set(file, (membership.get(file) ?? 0) + 1);
    functions.push(...(manifest.functions ?? []));
  }
  const missingMembership = scope.files.filter(file => file.function_inventory_required && membership.get(file.path) !== 1);
  if (missingMembership.length > 0) throw new Error(`Function manifest membership is incomplete for ${missingMembership.map(file => file.path).join(", ")}`);

  let aiSurfacesPath = null;
  if (args.agent === AI_AGENT) {
    aiSurfacesPath = resolve(args["ai-surfaces"]);
    const aiSurfaces = JSON.parse(await readFile(aiSurfacesPath, "utf8"));
    if (aiSurfaces.audit_id !== args["audit-id"] || aiSurfaces.scope_digest !== scope.scope_digest
      || !Array.isArray(aiSurfaces.items) || !Array.isArray(aiSurfaces.gaps)) {
      throw new Error("AI surface inventory is incomplete or scope-mismatched");
    }
  }

  const isAiOverlay = args.agent === AI_AGENT;
  const coverageDomain = isAiOverlay ? "ai" : "base";
  const ownedFiles = scope.files.filter(file => file.review_required && (isAiOverlay || file.owner_agent === args.agent));
  const ownedFunctions = functions.filter(fn => isAiOverlay || fn.owner_agent === args.agent);
  const domain = [...DOMAIN_AGENT].find(([, agent]) => agent === args.agent)?.[0] ?? null;
  const domainCatalog = domain ? catalog.entries.filter(entry => entry.applies_to.includes(domain)) : [];
  const focusAssignments = focusArea.assignments?.filter(item => item.agent_name === args.agent) ?? [];
  if (focusAssignments.length !== 1) throw new Error(`Focus Area must contain exactly one assignment for ${args.agent}`);
  const focusAssignment = focusAssignments[0];
  if (focusAssignment.language !== args.language || focusAssignment.file_function_domain !== coverageDomain
    || (domain && focusAssignment.catalog_domain !== domain)) {
    throw new Error(`Focus Area assignment does not match ${args.agent}/${args.language}/${coverageDomain}/${domain ?? "none"}`);
  }
  let assignment = {
    file_ids: args["file-id"].length > 0 ? args["file-id"] : focusAssignment.file_ids,
    function_ids: args["function-id"].length > 0 ? args["function-id"] : focusAssignment.function_ids,
    catalog_ids: args["catalog-id"].length > 0 ? args["catalog-id"] : focusAssignment.catalog_ids,
  };
  if (args.assignment) {
    assignment = JSON.parse(await readFile(resolve(args.assignment), "utf8"));
    for (const field of ["file_ids", "function_ids", "catalog_ids"]) {
      if (!Array.isArray(assignment[field])) throw new Error(`Assignment file must contain array ${field}`);
      const outsideFocus = assignment[field].filter(id => !focusAssignment[field].includes(id));
      if (outsideFocus.length > 0) throw new Error(`Follow-up assignment contains IDs outside Focus Area ${args["focus-area"]}: ${outsideFocus.join(", ")}`);
    }
  }
  const assignedFiles = selectAssignment(ownedFiles, assignment.file_ids, "file_id", "file-id");
  const assignedFunctions = selectAssignment(ownedFunctions, assignment.function_ids, "function_id", "function-id");
  const applicableCatalog = selectAssignment(domainCatalog, assignment.catalog_ids, "id", "catalog-id");

  const report = {
    schema_version: 1,
    audit_id: args["audit-id"],
    round: args.round,
    agent_name: args.agent,
    agent_session_id: args.session,
    scope_digest: scope.scope_digest,
    focus_area_id: focusArea.focus_area_id,
    discovery_track: "coverage",
    entry_point_ids: focusArea.entry_point_ids ?? [],
    threat_ids: focusArea.threat_ids ?? [],
    scope: {
      scope_manifest: scopePath,
      scope_digest: scope.scope_digest,
      assigned_file_ids: assignedFiles.map(file => file.file_id),
      assigned_function_ids: assignedFunctions.map(fn => fn.function_id),
      assigned_catalog_ids: applicableCatalog.map(entry => entry.id),
      focus_assignment_id: focusAssignment.assignment_id,
    },
    language: args.language,
    audit_strategy: args.lens,
    dimensions: DIMENSIONS,
    tool_inputs: [
      { kind: "scope-manifest", path: scopePath, scope_digest: scope.scope_digest },
      ...manifestPaths.map(path => ({ kind: "function-manifest", path })),
      { kind: "vulnerability-catalog", path: catalogPath, profile_id: catalog.profile_id },
      { kind: "threat-model", path: threatModelPath, scope_digest: scope.scope_digest, manifest_digest: threatModel.manifest_digest },
      { kind: "focus-areas", path: focusAreasPath, scope_digest: scope.scope_digest, manifest_digest: focusManifest.manifest_digest, focus_area_id: focusArea.focus_area_id, assignment_id: focusAssignment.assignment_id },
      ...(aiSurfacesPath ? [{ kind: "ai-surfaces", path: aiSurfacesPath, scope_digest: scope.scope_digest }] : []),
      ...(args.assignment ? [{ kind: "follow-up-assignment", path: resolve(args.assignment) }] : []),
    ],
    coverage_cells: DIMENSIONS.map(dimension => ({
      dimension,
      lens: args.lens,
      status: "GAP",
      targets_discovered: null,
      targets_reviewed: 0,
      evidence: [{ kind: "initialized-from-manifests" }],
      finding_ids: [],
      gap_reason: "audit-not-yet-completed",
      na_reason: null,
    })),
    review_depth: {
      files_read: [],
      functions_read: [],
      dataflow_paths_traced: [],
      call_paths_expanded: [],
      searches_executed: [],
      notes: "Populate with actual review activity; this is an anomaly signal and never substitutes for exact accounting records.",
    },
    file_coverage: assignedFiles.map(file => ({
      ...gapRecord("file_id", file.file_id, DIMENSIONS, { path: file.path, sha256: file.sha256 ?? null, scope_digest: scope.scope_digest }, "file-not-yet-reviewed"),
      domain: coverageDomain,
    })),
    function_coverage: assignedFunctions.map(fn => ({
      ...gapRecord("function_id", fn.function_id, DIMENSIONS, { path: fn.path, qualified_name: fn.qualified_name, code_sha256: fn.code_sha256 }, "function-not-yet-reviewed"),
      domain: coverageDomain,
    })),
    catalog_coverage: applicableCatalog.map(entry => ({
      ...gapRecord("catalog_id", entry.id, entry.dimensions, { catalog_profile: catalog.profile_id, lens_question: entry[`${args.lens.split("-")[0]}_question`] }, "catalog-item-not-yet-reviewed"),
      domain,
    })),
    findings: [],
    artifacts: [],
    learning_candidates: [],
  };

  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: outputPath, agent: args.agent, focus_area_id: focusArea.focus_area_id, assignment_id: focusAssignment.assignment_id, discovery_track: "coverage", coverage_domain: coverageDomain, lens: args.lens, files: assignedFiles.length, functions: assignedFunctions.length, catalog: applicableCatalog.length, all_records_initialized_as: "GAP" })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
