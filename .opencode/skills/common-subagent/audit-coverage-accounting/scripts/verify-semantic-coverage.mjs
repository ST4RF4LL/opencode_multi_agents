#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, readdir, mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

const LENSES = ["sink-driven", "control-driven", "config-driven"];
const DIMENSIONS = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);
const DISCOVERY_TRACKS = ["coverage", "blind", "seeded-variant"];
const CLOSED = new Set(["PASS", "FINDING"]);
const DOMAIN_AGENT = new Map([
  ["java", "java-source-auditor"],
  ["web", "web-source-auditor"],
  ["platform", "platform-security-auditor"],
  ["ai", "ai-security-auditor"],
]);

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["audit-id", "snapshot-index", "reports-dir", "attack-chain-report", "output"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  }
  return args;
}

function digestObject(value, field = "manifest_digest") {
  const copy = { ...value };
  delete copy[field];
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

function digestBytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function exactSet(left, right) {
  return Array.isArray(left) && Array.isArray(right)
    && left.length === right.length
    && new Set(left).size === left.length
    && right.every(value => left.includes(value));
}

function nonEmptyEvidence(value) {
  return Array.isArray(value) && value.length > 0 && value.every(item => {
    if (typeof item === "string") return item.trim().length > 0;
    return item && typeof item === "object" && Object.keys(item).length > 0;
  });
}

function pushInvalid(invalid, kind, id, errors) {
  if (errors.length > 0) invalid.push({ kind, id, errors: [...new Set(errors)] });
}

async function listReports(directory) {
  const files = [];
  async function visit(path) {
    let entries;
    try {
      entries = await readdir(path, { withFileTypes: true });
    } catch (error) {
      if (error.code === "ENOENT") return;
      throw error;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) await visit(child);
      else if (entry.isFile() && (entry.name.endsWith(".audit-report.json") || entry.name.endsWith(".discovery.json"))) files.push(child);
    }
  }
  await visit(directory);
  return files;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const issues = [];
  const warnings = [];
  const invalid = [];
  const missing = { entry_points: [], threats: [], primary_assignments: [], focus_lenses: [], discovery_tracks: [], attack_chain: [] };
  const snapshotPath = resolve(args["snapshot-index"]);
  const snapshot = JSON.parse(await readFile(snapshotPath, "utf8"));
  if (snapshot.audit_id !== args["audit-id"] || snapshot.snapshot_digest !== digestObject(snapshot, "snapshot_digest")) {
    issues.push({ code: "SEMANTIC_SNAPSHOT_INVALID", message: "Snapshot index is modified or bound to another audit" });
  }
  if (!snapshot.semantic?.threat_model?.path || !snapshot.semantic?.focus_areas?.path) {
    throw new Error("Snapshot index lacks sealed threat-model and focus-areas inputs");
  }

  const threatPath = resolve(snapshot.semantic.threat_model.path);
  const focusPath = resolve(snapshot.semantic.focus_areas.path);
  const threatBytes = await readFile(threatPath);
  const focusBytes = await readFile(focusPath);
  if (snapshot.semantic.threat_model.sha256 !== digestBytes(threatBytes)) issues.push({ code: "THREAT_MODEL_SNAPSHOT_HASH_MISMATCH" });
  if (snapshot.semantic.focus_areas.sha256 !== digestBytes(focusBytes)) issues.push({ code: "FOCUS_AREAS_SNAPSHOT_HASH_MISMATCH" });
  const threatModel = JSON.parse(threatBytes.toString("utf8"));
  const focusManifest = JSON.parse(focusBytes.toString("utf8"));
  if (threatModel.audit_id !== args["audit-id"] || threatModel.scope_digest !== snapshot.scope_digest || threatModel.manifest_digest !== digestObject(threatModel)) {
    issues.push({ code: "THREAT_MODEL_INVALID", message: "Threat model is modified, incomplete, or scope-mismatched" });
  }
  if (focusManifest.audit_id !== args["audit-id"] || focusManifest.scope_digest !== snapshot.scope_digest
    || focusManifest.manifest_digest !== digestObject(focusManifest) || focusManifest.threat_model_digest !== threatModel.manifest_digest) {
    issues.push({ code: "FOCUS_AREAS_INVALID", message: "Focus Area manifest is modified, incomplete, or threat-model-mismatched" });
  }
  if (!exactSet(focusManifest.required_lenses, LENSES)) issues.push({ code: "FOCUS_LENSES_INVALID" });

  const scope = JSON.parse(await readFile(resolve(snapshot.scope.path), "utf8"));
  const functionManifests = await Promise.all((snapshot.functions ?? []).map(async item => JSON.parse(await readFile(resolve(item.path), "utf8"))));
  const catalog = JSON.parse(await readFile(resolve(snapshot.catalog.path), "utf8"));
  const expectedPrimary = new Set();
  const activeCatalogDomains = new Set(["ai"]);
  for (const file of scope.files ?? []) {
    if (!file.review_required) continue;
    expectedPrimary.add(`${file.owner_agent}|base|file|${file.file_id}`);
    expectedPrimary.add(`ai-security-auditor|ai|file|${file.file_id}`);
    for (const [domain, agent] of DOMAIN_AGENT) if (file.owner_agent === agent) activeCatalogDomains.add(domain);
  }
  for (const fn of functionManifests.flatMap(manifest => manifest.functions ?? [])) {
    expectedPrimary.add(`${fn.owner_agent}|base|function|${fn.function_id}`);
    expectedPrimary.add(`ai-security-auditor|ai|function|${fn.function_id}`);
  }
  for (const entry of catalog.entries ?? []) {
    for (const domain of (entry.applies_to ?? []).filter(value => activeCatalogDomains.has(value))) {
      expectedPrimary.add(`${DOMAIN_AGENT.get(domain)}|${domain}|catalog|${entry.id}`);
    }
  }

  const assets = new Map((threatModel.assets ?? []).map(item => [item.asset_id, item]));
  const actors = new Map((threatModel.actors ?? []).map(item => [item.actor_id, item]));
  const boundaries = new Map((threatModel.trust_boundaries ?? []).map(item => [item.trust_boundary_id, item]));
  const entryPoints = new Map((threatModel.entry_points ?? []).map(item => [item.entry_point_id, item]));
  const threats = new Map((threatModel.threats ?? []).map(item => [item.threat_id, item]));
  const historyClusters = new Map((threatModel.history_clusters ?? []).map(item => [item.cluster_id, item]));
  for (const [name, map, source] of [
    ["asset", assets, threatModel.assets],
    ["actor", actors, threatModel.actors],
    ["trust-boundary", boundaries, threatModel.trust_boundaries],
    ["entry-point", entryPoints, threatModel.entry_points],
    ["threat", threats, threatModel.threats],
    ["history-cluster", historyClusters, threatModel.history_clusters],
  ]) {
    if (map.has(undefined) || map.size !== (source ?? []).length) issues.push({ code: `DUPLICATE_OR_INVALID_${name.toUpperCase().replace("-", "_")}_ID` });
  }

  for (const [id, entry] of entryPoints) {
    const errors = [];
    if (!nonEmptyEvidence(entry.evidence)) errors.push("missing-evidence");
    if (!Array.isArray(entry.trust_boundary_ids) || entry.trust_boundary_ids.some(ref => !boundaries.has(ref))) errors.push("unknown-trust-boundary");
    if (!Array.isArray(entry.reachable_asset_ids) || entry.reachable_asset_ids.some(ref => !assets.has(ref))) errors.push("unknown-asset");
    pushInvalid(invalid, "entry-point", id, errors);
  }
  for (const [id, threat] of threats) {
    const errors = [];
    if (typeof threat.outcome !== "string" || threat.outcome.length < 12) errors.push("outcome-too-thin");
    if (!Array.isArray(threat.actor_ids) || threat.actor_ids.length === 0 || threat.actor_ids.some(ref => !actors.has(ref))) errors.push("unknown-or-empty-actors");
    if (!Array.isArray(threat.entry_point_ids) || threat.entry_point_ids.length === 0 || threat.entry_point_ids.some(ref => !entryPoints.has(ref))) errors.push("unknown-or-empty-entry-points");
    if (!Array.isArray(threat.trust_boundary_ids) || threat.trust_boundary_ids.some(ref => !boundaries.has(ref))) errors.push("unknown-trust-boundary");
    if (!Array.isArray(threat.asset_ids) || threat.asset_ids.length === 0 || threat.asset_ids.some(ref => !assets.has(ref))) errors.push("unknown-or-empty-assets");
    if (!Array.isArray(threat.dimensions) || threat.dimensions.length === 0 || threat.dimensions.some(value => !DIMENSIONS.includes(value))) errors.push("invalid-dimensions");
    if (!Array.isArray(threat.provenance_tags) || threat.provenance_tags.length === 0) errors.push("missing-provenance");
    pushInvalid(invalid, "threat", id, errors);
  }

  const entryCoverage = new Map();
  for (const record of threatModel.entry_point_coverage ?? []) {
    if (entryCoverage.has(record.entry_point_id)) issues.push({ code: "DUPLICATE_ENTRY_POINT_COVERAGE", entry_point_id: record.entry_point_id });
    entryCoverage.set(record.entry_point_id, record);
  }
  for (const id of entryPoints.keys()) {
    const record = entryCoverage.get(id);
    if (!record) {
      missing.entry_points.push({ entry_point_id: id, reason: "coverage-record-missing" });
      continue;
    }
    const errors = [];
    if (!nonEmptyEvidence(record.evidence)) errors.push("missing-evidence");
    if (record.status === "THREAT") {
      if (!Array.isArray(record.threat_ids) || record.threat_ids.length === 0 || record.threat_ids.some(ref => !threats.has(ref) || !threats.get(ref).entry_point_ids.includes(id))) errors.push("invalid-threat-ids");
    } else if (record.status === "DEPRIORITIZED") {
      if (typeof record.reason !== "string" || record.reason.length < 8) errors.push("invalid-deprioritized-reason");
    } else errors.push("non-terminal-entry-point-status");
    pushInvalid(invalid, "entry-point-coverage", id, errors);
  }
  for (const id of entryCoverage.keys()) if (!entryPoints.has(id)) invalid.push({ kind: "entry-point-coverage", id, errors: ["unknown-entry-point"] });
  for (const id of threats.keys()) {
    if (![...entryCoverage.values()].some(record => record.status === "THREAT" && record.threat_ids?.includes(id))) missing.threats.push({ threat_id: id, reason: "not-linked-from-entry-point-coverage" });
  }
  for (const question of threatModel.open_questions ?? []) {
    if (question.blocking === true && question.status !== "resolved") issues.push({ code: "BLOCKING_THREAT_MODEL_QUESTION", question_id: question.question_id });
  }

  const focusAreas = new Map();
  const assignmentEntityKeys = new Set();
  const expectedSessions = [];
  for (const focus of focusManifest.focus_areas ?? []) {
    const id = focus.focus_area_id;
    const errors = [];
    if (typeof id !== "string" || focusAreas.has(id)) errors.push("invalid-or-duplicate-id");
    focusAreas.set(id, focus);
    if (!Array.isArray(focus.required_discovery_tracks) || !focus.required_discovery_tracks.includes("coverage") || !focus.required_discovery_tracks.includes("blind")
      || focus.required_discovery_tracks.some(track => !DISCOVERY_TRACKS.includes(track))) errors.push("invalid-required-discovery-tracks");
    if ((focus.history_cluster_ids?.length ?? 0) > 0 && !focus.required_discovery_tracks?.includes("seeded-variant")) errors.push("history-area-missing-seeded-variant-track");
    if (!Array.isArray(focus.entry_point_ids) || focus.entry_point_ids.some(ref => !entryPoints.has(ref))) errors.push("unknown-entry-point");
    if (!Array.isArray(focus.threat_ids) || focus.threat_ids.some(ref => !threats.has(ref))) errors.push("unknown-threat");
    if (!Array.isArray(focus.trust_boundary_ids) || focus.trust_boundary_ids.some(ref => !boundaries.has(ref))) errors.push("unknown-trust-boundary");
    if (!Array.isArray(focus.asset_ids) || focus.asset_ids.some(ref => !assets.has(ref))) errors.push("unknown-asset");
    if (!Array.isArray(focus.history_cluster_ids) || focus.history_cluster_ids.some(ref => !historyClusters.has(ref))) errors.push("unknown-history-cluster");
    if (!Array.isArray(focus.assignments) || focus.assignments.length === 0) errors.push("assignments-missing");
    for (const assignment of focus.assignments ?? []) {
      const assignmentErrors = [];
      for (const field of ["file_ids", "function_ids", "catalog_ids"]) if (!Array.isArray(assignment[field]) || new Set(assignment[field]).size !== assignment[field].length) assignmentErrors.push(`${field}-invalid`);
      if (typeof assignment.assignment_id !== "string" || typeof assignment.agent_name !== "string" || typeof assignment.language !== "string") assignmentErrors.push("identity-fields-missing");
      if (!["base", "ai"].includes(assignment.file_function_domain)) assignmentErrors.push("file-function-domain-invalid");
      if ((assignment.file_ids?.length ?? 0) + (assignment.function_ids?.length ?? 0) + (assignment.catalog_ids?.length ?? 0) === 0) assignmentErrors.push("empty-assignment");
      for (const [kind, field] of [["file", "file_ids"], ["function", "function_ids"], ["catalog", "catalog_ids"]]) {
        for (const entityId of assignment[field] ?? []) {
          const entityDomain = kind === "catalog" ? assignment.catalog_domain : assignment.file_function_domain;
          const key = `${assignment.agent_name}|${entityDomain ?? "none"}|${kind}|${entityId}`;
          if (assignmentEntityKeys.has(key)) assignmentErrors.push(`duplicate-primary-${kind}:${entityId}`);
          assignmentEntityKeys.add(key);
        }
      }
      for (const lens of LENSES) expectedSessions.push({ focus_area_id: id, focus, assignment, lens });
      pushInvalid(invalid, "focus-assignment", assignment.assignment_id ?? `${id}:unknown`, assignmentErrors);
    }
    pushInvalid(invalid, "focus-area", id ?? "unknown", errors);
  }
  if ((focusManifest.gaps?.length ?? 0) > 0) issues.push({ code: "FOCUS_MANIFEST_GAPS", gaps: focusManifest.gaps });
  for (const key of expectedPrimary) if (!assignmentEntityKeys.has(key)) missing.primary_assignments.push({ key });
  for (const key of assignmentEntityKeys) if (!expectedPrimary.has(key)) invalid.push({ kind: "primary-assignment", id: key, errors: ["not-in-frozen-structural-universe"] });

  for (const [id, record] of entryCoverage) {
    if (record.status === "THREAT" && ![...focusAreas.values()].some(focus => focus.entry_point_ids.includes(id))) missing.entry_points.push({ entry_point_id: id, reason: "no-focus-area" });
  }
  for (const id of threats.keys()) {
    if (![...focusAreas.values()].some(focus => focus.threat_ids.includes(id))) missing.threats.push({ threat_id: id, reason: "no-focus-area" });
  }

  const reportFiles = await listReports(resolve(args["reports-dir"]));
  const reports = [];
  for (const path of reportFiles) {
    try {
      const report = JSON.parse(await readFile(path, "utf8"));
      if (report.audit_id === args["audit-id"]) reports.push({ path, report });
    } catch (error) {
      issues.push({ code: "SEMANTIC_REPORT_UNREADABLE", path, message: error.message });
    }
  }

  const completedFocusLenses = new Set();
  for (const expected of expectedSessions) {
    const { focus_area_id: focusId, assignment, lens } = expected;
    const matches = reports.filter(({ report }) => report.discovery_track === "coverage"
      && report.focus_area_id === focusId
      && report.agent_name === assignment.agent_name
      && report.audit_strategy === lens
      && (report.scope_digest ?? report.scope?.scope_digest) === snapshot.scope_digest
      && exactSet(report.scope?.assigned_file_ids, assignment.file_ids)
      && exactSet(report.scope?.assigned_function_ids, assignment.function_ids)
      && exactSet(report.scope?.assigned_catalog_ids, assignment.catalog_ids));
    if (matches.length === 0) {
      missing.focus_lenses.push({ focus_area_id: focusId, assignment_id: assignment.assignment_id, lens });
      continue;
    }
    const latestRound = Math.max(...matches.map(({ report }) => report.round));
    const latest = matches.filter(({ report }) => report.round === latestRound);
    if (latest.length !== 1) invalid.push({ kind: "focus-lens-session", id: `${focusId}|${assignment.assignment_id}|${lens}`, errors: ["ambiguous-latest-report"] });
    else {
      completedFocusLenses.add(`${focusId}|${lens}`);
      const depth = latest[0].report.review_depth;
      if (!depth || !Array.isArray(depth.files_read) || !Array.isArray(depth.functions_read)) {
        warnings.push({ code: "COVERAGE_DEPTH_UNAVAILABLE", focus_area_id: focusId, assignment_id: assignment.assignment_id, lens, report: latest[0].path });
      } else {
        if (assignment.file_ids.length > 0 && depth.files_read.length === 0) warnings.push({ code: "NO_FILES_RECORDED_AS_READ", focus_area_id: focusId, assignment_id: assignment.assignment_id, lens, report: latest[0].path });
        if (assignment.function_ids.length > 0 && depth.functions_read.length === 0) warnings.push({ code: "NO_FUNCTIONS_RECORDED_AS_READ", focus_area_id: focusId, assignment_id: assignment.assignment_id, lens, report: latest[0].path });
      }
    }
  }

  for (const focus of focusAreas.values()) {
    for (const track of focus.required_discovery_tracks ?? []) {
      if (track === "coverage") continue;
      const matches = reports.filter(({ report }) => report.focus_area_id === focus.focus_area_id && report.discovery_track === track);
      const valid = matches.some(({ report }) => CLOSED.has(report.status)
        && focus.assignments.some(assignment => assignment.agent_name === report.agent_name)
        && report.scope_digest === snapshot.scope_digest
        && Array.isArray(report.gaps) && report.gaps.length === 0
        && Array.isArray(report.files_read) && Array.isArray(report.functions_read)
        && Array.isArray(report.hypotheses_tested) && report.hypotheses_tested.length > 0
        && nonEmptyEvidence(report.evidence)
        && (track === "blind" ? Array.isArray(report.seed_inputs) && report.seed_inputs.length === 0 : Array.isArray(report.seed_inputs) && report.seed_inputs.length > 0));
      if (!valid) missing.discovery_tracks.push({ focus_area_id: focus.focus_area_id, discovery_track: track });
    }
  }

  for (const [threatId] of threats) {
    const owningFocus = [...focusAreas.values()].filter(focus => focus.threat_ids.includes(threatId));
    for (const lens of LENSES) {
      if (!owningFocus.some(focus => completedFocusLenses.has(`${focus.focus_area_id}|${lens}`))) missing.threats.push({ threat_id: threatId, lens, reason: "no-complete-focus-lens" });
    }
  }

  const attackPath = resolve(args["attack-chain-report"]);
  const attack = JSON.parse(await readFile(attackPath, "utf8"));
  if (attack.audit_id !== args["audit-id"] || attack.scope_digest !== snapshot.scope_digest
    || attack.threat_model_digest !== threatModel.manifest_digest || attack.focus_areas_digest !== focusManifest.manifest_digest) {
    invalid.push({ kind: "attack-chain-report", id: attackPath, errors: ["identity-or-digest-mismatch"] });
  }
  if (!CLOSED.has(attack.status) || !Array.isArray(attack.gaps) || attack.gaps.length > 0 || !nonEmptyEvidence(attack.evidence)) {
    invalid.push({ kind: "attack-chain-report", id: attackPath, errors: ["non-terminal-or-missing-evidence"] });
  }
  for (const [field, expected] of [
    ["reviewed_focus_area_ids", [...focusAreas.keys()]],
    ["reviewed_trust_boundary_ids", [...boundaries.keys()]],
    ["reviewed_asset_ids", [...assets.keys()]],
  ]) {
    if (!exactSet(attack[field], expected)) missing.attack_chain.push({ field, expected, observed: attack[field] ?? null });
  }

  const complete = issues.length === 0 && invalid.length === 0 && Object.values(missing).every(items => items.length === 0);
  const verification = {
    schema_version: 1,
    audit_id: args["audit-id"],
    scope_digest: snapshot.scope_digest,
    threat_model_digest: threatModel.manifest_digest,
    focus_areas_digest: focusManifest.manifest_digest,
    inputs: { snapshot_index: snapshotPath, threat_model: threatPath, focus_areas: focusPath, reports_directory: resolve(args["reports-dir"]), attack_chain_report: attackPath },
    expected: { entry_points: entryPoints.size, threats: threats.size, focus_areas: focusAreas.size, primary_assignments: expectedPrimary.size, focus_assignment_lens_sessions: expectedSessions.length, trust_boundaries: boundaries.size, assets: assets.size },
    observed: { reports: reports.length, completed_focus_lenses: completedFocusLenses.size },
    missing,
    invalid,
    issues,
    warnings,
    complete,
    claim_boundary: "Proves terminal entry-point threat decisions, threat-to-Focus mapping, exact Focus Area assignment sessions across all three lenses, required blind/seeded discovery tracks, and a system-level pass over every Focus Area, trust boundary, and asset. It does not prove that every possible threat or vulnerability was recognized, nor that runtime-only assumptions are true.",
  };
  const outputPath = resolve(args.output);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(verification, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: outputPath, complete, missing: Object.fromEntries(Object.entries(missing).map(([key, value]) => [key, value.length])), invalid: invalid.length, issues: issues.length, warnings: warnings.length })}\n`);
  if (!complete) process.exitCode = 2;
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
