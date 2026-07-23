#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile, mkdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import { catalogQuestionDigest, deriveCoverageCells } from "./coverage-cell-accounting.mjs";

const LENSES = ["sink-driven", "control-driven", "config-driven"];
const DIMENSIONS = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);
const CLOSED_STATUSES = new Set(["REVIEWED", "FINDING"]);
const ALL_STATUSES = new Set([...CLOSED_STATUSES, "GAP"]);
const DIMENSION_STATUSES = new Set(["PASS", "FINDING", "N/A", "GAP"]);
const PARSER_LANGUAGE = new Map([
  ["javac-java", "java"],
  ["joern-js", "javascript"],
  ["joern-python", "python"],
  ["joern-c", "c"],
  ["joern-cpp", "cpp"],
  ["joern-kotlin", "kotlin"],
  ["joern-jvm", "jvm"],
  ["embedded-web", "embedded-web"],
]);
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
const COVERAGE_DOMAINS = ["base", "ai"];

function parseArgs(argv) {
  const args = { functions: [] };
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    const key = token.slice(2);
    if (key === "functions") args.functions.push(value);
    else args[key] = value;
  }
  for (const key of ["root", "audit-id", "scope", "interfaces", "interface-extractors", "snapshot-index", "reports-dir", "catalog", "output"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  }
  if (args.functions.length === 0) throw new Error("At least one --functions manifest is required");
  return args;
}

function pushIssue(issues, code, message, details = {}) {
  issues.push({ code, message, ...details });
}

function exactStringSet(value, required) {
  return Array.isArray(value)
    && value.length === required.length
    && new Set(value).size === value.length
    && required.every(item => value.includes(item));
}

function contentDigest(value) {
  const copy = { ...value };
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

function snapshotDigest(value) {
  const copy = { ...value };
  delete copy.snapshot_digest;
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

async function fileDigest(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function evidenceErrors(record, context) {
  if (!Array.isArray(record?.evidence) || record.evidence.length === 0) return ["missing-evidence"];
  const errors = [];
  let hasConcreteAnchor = false;
  let hasAssignmentAnchor = false;
  for (const item of record.evidence) {
    if (!item || typeof item !== "object" || Array.isArray(item) || typeof item.kind !== "string") {
      errors.push("invalid-evidence-item");
      continue;
    }
    if (item.kind === "assignment-anchor") {
      if (item.target_kind !== context.kind || item.target_id !== context.id) errors.push("assignment-anchor-mismatch");
      else hasAssignmentAnchor = true;
      continue;
    }
    if (context.kind === "file" && item.kind === "source-location") {
      if (context.file.type === "symlink" || item.file_id !== context.file.file_id || item.path !== context.file.path || item.sha256 !== context.file.sha256
        || !Number.isInteger(item.line_start) || item.line_start < 1) errors.push("file-evidence-not-bound-to-frozen-source");
      else hasConcreteAnchor = true;
      continue;
    }
    if (context.kind === "file" && item.kind === "symlink-location") {
      if (context.file.type !== "symlink" || item.file_id !== context.file.file_id || item.path !== context.file.path
        || item.link_target !== context.file.link_target) errors.push("symlink-evidence-not-bound-to-frozen-target");
      else hasConcreteAnchor = true;
      continue;
    }
    if (context.kind === "function" && item.kind === "function-location") {
      if (item.function_id !== context.fn.function_id || item.path !== context.fn.path || item.code_sha256 !== context.fn.code_sha256
        || item.qualified_name !== context.fn.qualified_name || item.line_start !== context.fn.line_start) errors.push("function-evidence-not-bound-to-frozen-source");
      else hasConcreteAnchor = true;
      continue;
    }
    if (context.kind === "catalog" && item.kind === "catalog-review") {
      if (item.catalog_id !== context.entry.id || item.domain !== context.domain || item.lens !== context.lens
        || item.catalog_profile !== context.catalog.profile_id || item.question_sha256 !== catalogQuestionDigest(context.entry, context.lens)) {
        errors.push("catalog-evidence-not-bound-to-frozen-question");
      } else hasConcreteAnchor = true;
      continue;
    }
    errors.push("unsupported-evidence-kind");
  }
  if (record.status === "GAP" && !hasAssignmentAnchor) errors.push("gap-missing-assignment-anchor");
  if (["REVIEWED", "FINDING"].includes(record.status) && !hasConcreteAnchor) errors.push("closed-record-missing-bound-evidence");
  return [...new Set(errors)];
}

function validateCoverageRecord(record, idField, expectedId, requiredDimensions, findingIds, context) {
  const errors = [];
  if (!record || typeof record !== "object") return ["record-not-object"];
  if (record[idField] !== expectedId) errors.push(`${idField}-mismatch`);
  if (!ALL_STATUSES.has(record.status)) errors.push("invalid-status");
  errors.push(...evidenceErrors(record, context));
  if (!exactStringSet(record.dimensions_reviewed, requiredDimensions)) errors.push("dimensions-not-complete");
  if (record.status === "FINDING") {
    if (!Array.isArray(record.finding_ids) || record.finding_ids.length === 0) errors.push("finding-ids-missing");
    else if (record.finding_ids.some(id => !findingIds.has(id))) errors.push("finding-id-not-in-report");
  }
  if (record.status === "GAP") errors.push("gap-status");
  return errors;
}

function validateDimensionCells(report, catalogEntries) {
  const errors = [];
  const cells = report.coverage_cells;
  if (!Array.isArray(cells) || cells.length !== DIMENSIONS.length) return ["dimension-cell-count-mismatch"];
  let expectedCells;
  try {
    expectedCells = deriveCoverageCells(report, catalogEntries);
  } catch (error) {
    return [`machine-cell-derivation-failed:${error.message}`];
  }
  const expectedByDimension = new Map(expectedCells.map(cell => [cell.dimension, cell]));
  const seen = new Set();
  for (const cell of cells) {
    if (!DIMENSIONS.includes(cell?.dimension) || seen.has(cell.dimension)) errors.push("invalid-or-duplicate-dimension");
    else seen.add(cell.dimension);
    if (cell?.lens !== report.audit_strategy) errors.push(`${cell?.dimension ?? "unknown"}:lens-mismatch`);
    if (!DIMENSION_STATUSES.has(cell?.status)) errors.push(`${cell?.dimension ?? "unknown"}:invalid-status`);
    if (Object.hasOwn(cell ?? {}, "targets_discovered") || Object.hasOwn(cell ?? {}, "targets_reviewed")) errors.push(`${cell?.dimension ?? "unknown"}:self-reported-target-count-forbidden`);
    const expected = expectedByDimension.get(cell?.dimension);
    if (!expected) continue;
    const sameDerivedCell = cell.status === expected.status
      && exactStringSet(cell.finding_ids ?? [], expected.finding_ids)
      && cell.gap_reason === expected.gap_reason
      && cell.na_reason === expected.na_reason
      && Array.isArray(cell.evidence) && cell.evidence.length === 1
      && isDeepStrictEqual(cell.evidence[0], expected.evidence[0]);
    if (!sameDerivedCell) errors.push(`${cell.dimension}:machine-derived-cell-mismatch`);
    if (cell?.status === "GAP") errors.push(`${cell.dimension}:gap-status`);
  }
  if (!DIMENSIONS.every(dimension => seen.has(dimension))) errors.push("dimension-missing");
  return [...new Set(errors)];
}

async function listAuditReports(directory) {
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
      else if (entry.isFile() && entry.name.endsWith(".audit-report.json")) files.push(child);
    }
  }
  await visit(directory);
  return files;
}

function selectLatest(records, key, issues) {
  const byRound = [...records].sort((a, b) => b.round - a.round);
  if (byRound.length === 0) return null;
  const latestRound = byRound[0].round;
  const latest = byRound.filter(record => record.round === latestRound);
  if (latest.length !== 1) {
    pushIssue(issues, "AMBIGUOUS_LATEST_COVERAGE", "More than one coverage record exists at the latest round", {
      key,
      round: latestRound,
      reports: latest.map(record => record.report_path),
    });
    return null;
  }
  return latest[0];
}

async function buildCurrentScope(root, auditId, frozenScope) {
  const work = await mkdtemp(join(tmpdir(), "opencode-coverage-"));
  const output = join(work, "scope.json");
  const script = resolve(dirname(fileURLToPath(import.meta.url)), "build-scope-manifest.mjs");
  try {
    const frozenMode = frozenScope.policy?.requested_mode
      ?? (frozenScope.policy?.enumeration === "recursive-filesystem-walk" ? "filesystem" : "auto");
    const result = spawnSync(process.execPath, [script, "--root", root, "--audit-id", auditId, "--output", output, "--mode", frozenMode], {
      encoding: "utf8",
      maxBuffer: 128 * 1024 * 1024,
    });
    if (result.status !== 0) throw new Error(`Scope rebuild failed (${result.status})\n${result.stderr}\n${result.stdout}`);
    return JSON.parse(await readFile(output, "utf8"));
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = resolve(args.root);
  const outputPath = resolve(args.output);
  const scope = JSON.parse(await readFile(resolve(args.scope), "utf8"));
  const catalog = JSON.parse(await readFile(resolve(args.catalog), "utf8"));
  const issues = [];

  const snapshotIndexPath = resolve(args["snapshot-index"]);
  try {
    const snapshot = JSON.parse(await readFile(snapshotIndexPath, "utf8"));
    if (snapshot.audit_id !== args["audit-id"] || snapshot.scope_digest !== scope.scope_digest || snapshot.snapshot_digest !== snapshotDigest(snapshot)) {
      pushIssue(issues, "SNAPSHOT_INDEX_INVALID", "Durable coverage snapshot index is modified, incomplete, or bound to another audit");
    }
    const requestedFunctions = args.functions.map(path => resolve(path)).sort();
    const indexedFunctions = (snapshot.functions ?? []).map(item => resolve(item.path)).sort();
    if (resolve(snapshot.scope?.path ?? "") !== resolve(args.scope)
      || resolve(snapshot.interfaces?.path ?? "") !== resolve(args.interfaces)
      || resolve(snapshot.interface_extractors?.path ?? "") !== resolve(args["interface-extractors"])
      || resolve(snapshot.catalog?.path ?? "") !== resolve(args.catalog)
      || !exactStringSet(requestedFunctions, indexedFunctions)) {
      pushIssue(issues, "SNAPSHOT_INPUT_SET_MISMATCH", "Verifier inputs do not exactly equal the durable snapshot index");
    }
    if (snapshot.scope?.sha256 !== await fileDigest(resolve(args.scope))) pushIssue(issues, "SNAPSHOT_SCOPE_HASH_MISMATCH", "Durable scope snapshot hash mismatch");
    if (snapshot.interfaces?.sha256 !== await fileDigest(resolve(args.interfaces))) pushIssue(issues, "SNAPSHOT_INTERFACE_HASH_MISMATCH", "Durable interface snapshot hash mismatch");
    if (snapshot.interface_extractors?.sha256 !== await fileDigest(resolve(args["interface-extractors"]))) pushIssue(issues, "SNAPSHOT_INTERFACE_EXTRACTOR_HASH_MISMATCH", "Durable interface extractor verification hash mismatch");
    if (snapshot.catalog?.sha256 !== await fileDigest(resolve(args.catalog))) pushIssue(issues, "SNAPSHOT_CATALOG_HASH_MISMATCH", "Durable catalog snapshot hash mismatch");
    for (const item of snapshot.functions ?? []) {
      if (item.sha256 !== await fileDigest(resolve(item.path))) pushIssue(issues, "SNAPSHOT_FUNCTION_HASH_MISMATCH", "Durable function snapshot hash mismatch", { language: item.language, path: item.path });
    }
  } catch (error) {
    pushIssue(issues, "SNAPSHOT_VALIDATION_FAILED", error.message, { snapshot_index: snapshotIndexPath });
  }

  if (scope.audit_id !== args["audit-id"]) pushIssue(issues, "SCOPE_AUDIT_ID_MISMATCH", "Scope audit_id does not match requested audit");
  if (scope.manifest_digest !== contentDigest(scope)) pushIssue(issues, "SCOPE_MANIFEST_DIGEST_INVALID", "Frozen scope manifest content digest is missing or invalid");
  if (!scope.complete || (scope.errors?.length ?? 0) > 0) pushIssue(issues, "SCOPE_INCOMPLETE", "Frozen scope manifest is incomplete");
  if (!exactStringSet(scope.policy?.lenses, LENSES)) pushIssue(issues, "SCOPE_LENSES_INVALID", "Scope does not require the three canonical lenses");

  let currentScope = null;
  try {
    currentScope = await buildCurrentScope(root, args["audit-id"], scope);
    if (currentScope.manifest_digest !== contentDigest(currentScope)) pushIssue(issues, "CURRENT_SCOPE_MANIFEST_DIGEST_INVALID", "Rebuilt scope manifest digest is invalid");
    if (currentScope.scope_digest !== scope.scope_digest) {
      const frozen = new Map(scope.files.map(file => [file.path, file]));
      const current = new Map(currentScope.files.map(file => [file.path, file]));
      const added = [...current.keys()].filter(path => !frozen.has(path));
      const removed = [...frozen.keys()].filter(path => !current.has(path));
      const changed = [...current.keys()].filter(path => frozen.has(path)
        && (current.get(path).sha256 ?? current.get(path).link_target) !== (frozen.get(path).sha256 ?? frozen.get(path).link_target));
      pushIssue(issues, "SCOPE_DRIFT", "Repository contents changed after the scope was frozen", { added, removed, changed });
    }
    const frozenByPath = new Map(scope.files.map(file => [file.path, file]));
    const policyDrift = currentScope.files.flatMap(current => {
      const frozen = frozenByPath.get(current.path);
      if (!frozen) return [];
      const fields = ["file_id", "type", "owner_agent", "content_kind", "function_parser", "function_inventory_state", "function_inventory_reason", "function_inventory_required", "review_required"];
      const changedFields = fields.filter(field => JSON.stringify(current[field] ?? null) !== JSON.stringify(frozen[field] ?? null));
      if (!exactStringSet(frozen.required_lenses, current.required_lenses)) changedFields.push("required_lenses");
      return changedFields.length > 0 ? [{ path: current.path, changed_fields: changedFields }] : [];
    });
    const comparableCurrentPolicy = { ...currentScope.policy };
    if (!("requested_mode" in (scope.policy ?? {}))) delete comparableCurrentPolicy.requested_mode;
    if (!("ignored_content" in (scope.policy ?? {}))) delete comparableCurrentPolicy.ignored_content;
    const policyChanged = JSON.stringify(scope.policy) !== JSON.stringify(comparableCurrentPolicy);
    if (policyDrift.length > 0 || policyChanged) {
      pushIssue(issues, "SCOPE_POLICY_DRIFT", "Frozen owner/parser/lens policy differs from a current deterministic rebuild", { files: policyDrift, policy_changed: policyChanged });
    }
  } catch (error) {
    pushIssue(issues, "SCOPE_REBUILD_FAILED", error.message);
  }

  const scopeFiles = new Map();
  const scopeFilesByPath = new Map();
  for (const file of scope.files ?? []) {
    if (scopeFiles.has(file.file_id)) pushIssue(issues, "DUPLICATE_FILE_ID", "Duplicate file_id in scope", { file_id: file.file_id });
    scopeFiles.set(file.file_id, file);
    if (scopeFilesByPath.has(file.path)) pushIssue(issues, "DUPLICATE_SCOPE_PATH", "Duplicate path in scope", { path: file.path });
    scopeFilesByPath.set(file.path, file);
    if (!file.owner_agent || !exactStringSet(file.required_lenses, LENSES)) {
      pushIssue(issues, "INVALID_SCOPE_FILE", "Scope file lacks owner or canonical lens assignment", { file_id: file.file_id, path: file.path });
    }
    if (!["required", "not-applicable", "unsupported"].includes(file.function_inventory_state)) {
      pushIssue(issues, "FUNCTION_INVENTORY_STATE_MISSING", "Scope file lacks an explicit function inventory state", { file_id: file.file_id, path: file.path });
    }
    if (file.function_inventory_required !== (file.function_inventory_state === "required")
      || (file.function_inventory_state === "required" && (!file.function_parser || !PARSER_LANGUAGE.has(file.function_parser)))
      || (file.function_inventory_state !== "required" && file.function_parser !== null)) {
      pushIssue(issues, "FUNCTION_INVENTORY_POLICY_INVALID", "Scope function inventory state/parser/required fields are inconsistent", { file_id: file.file_id, path: file.path });
    }
    if (typeof file.function_inventory_reason !== "string" || !file.function_inventory_reason) {
      pushIssue(issues, "FUNCTION_INVENTORY_REASON_MISSING", "Scope file lacks a function inventory reason", { file_id: file.file_id, path: file.path });
    }
    if (file.function_inventory_state === "unsupported") {
      pushIssue(issues, "UNSUPPORTED_FUNCTION_INVENTORY", "Potential function-bearing file has no configured AST/CPG extractor", { file_id: file.file_id, path: file.path, reason: file.function_inventory_reason });
    }
  }

  let interfaceManifest = null;
  let interfaceExtractorCoverage = null;
  try {
    interfaceManifest = JSON.parse(await readFile(resolve(args.interfaces), "utf8"));
    interfaceExtractorCoverage = JSON.parse(await readFile(resolve(args["interface-extractors"]), "utf8"));
    if (interfaceManifest.audit_id !== args["audit-id"] || interfaceManifest.scope_digest !== scope.scope_digest
      || interfaceManifest.manifest_digest !== contentDigest(interfaceManifest)) {
      pushIssue(issues, "INTERFACE_MANIFEST_INVALID", "Interface manifest is modified or scope-mismatched");
    }
    if (interfaceExtractorCoverage.audit_id !== args["audit-id"] || interfaceExtractorCoverage.scope_digest !== scope.scope_digest
      || interfaceExtractorCoverage.interface_manifest_digest !== interfaceManifest.manifest_digest
      || interfaceExtractorCoverage.manifest_digest !== contentDigest(interfaceExtractorCoverage)
      || !interfaceExtractorCoverage.complete) {
      pushIssue(issues, "INTERFACE_EXTRACTOR_COVERAGE_INVALID", "Interface extractor verification is incomplete, modified, or manifest-mismatched");
    }
    if (!interfaceManifest.complete || (interfaceManifest.gaps?.length ?? 0) > 0) {
      pushIssue(issues, "INTERFACE_MANIFEST_INCOMPLETE", "Interface inventory contains unresolved extractor gaps");
    }
    const interfaceIds = new Set();
    for (const item of interfaceManifest.interfaces ?? []) {
      if (interfaceIds.has(item.interface_id)) pushIssue(issues, "DUPLICATE_INTERFACE_ID", "Interface manifest repeats interface_id", { interface_id: item.interface_id });
      interfaceIds.add(item.interface_id);
      const file = scopeFiles.get(item.file_id);
      if (!file || item.path !== file.path || item.owner_agent !== file.owner_agent || !exactStringSet(item.required_lenses, LENSES)
        || !["CONFIRMED", "CANDIDATE"].includes(item.discovery_state)) {
        pushIssue(issues, "INVALID_INTERFACE_SCOPE", "Interface is not bound to a frozen scoped file, owner, and canonical lenses", { interface_id: item.interface_id });
      }
    }
  } catch (error) {
    pushIssue(issues, "INTERFACE_INPUT_UNREADABLE", error.message);
  }

  const functionManifests = [];
  const functions = new Map();
  const manifestMembership = new Map();
  for (const manifestArg of args.functions) {
    const manifestPath = resolve(manifestArg);
    let manifest;
    try {
      manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    } catch (error) {
      pushIssue(issues, "FUNCTION_MANIFEST_UNREADABLE", error.message, { manifest: manifestPath });
      continue;
    }
    functionManifests.push({ path: manifestPath, manifest });
    if (![...new Set(PARSER_LANGUAGE.values())].includes(manifest.language)) {
      pushIssue(issues, "FUNCTION_MANIFEST_LANGUAGE_INVALID", "Function manifest has an unsupported language", { manifest: manifestPath, language: manifest.language });
    }
    if (manifest.manifest_digest !== contentDigest(manifest)) {
      pushIssue(issues, "FUNCTION_MANIFEST_DIGEST_INVALID", "Function manifest content digest is missing or invalid", { manifest: manifestPath });
    }
    if (manifest.audit_id !== args["audit-id"] || manifest.scope_digest !== scope.scope_digest) {
      pushIssue(issues, "FUNCTION_MANIFEST_SCOPE_MISMATCH", "Function manifest is not bound to the frozen scope", { manifest: manifestPath });
    }
    if (!manifest.complete || (manifest.missing_files?.length ?? 0) > 0 || (manifest.diagnostics?.length ?? 0) > 0) {
      pushIssue(issues, "FUNCTION_MANIFEST_INCOMPLETE", "Function manifest contains extraction gaps", { manifest: manifestPath });
    }
    for (const path of manifest.expected_files ?? []) {
      const memberships = manifestMembership.get(path) ?? [];
      memberships.push({ language: manifest.language, manifest: manifestPath });
      manifestMembership.set(path, memberships);
    }
    for (const fn of manifest.functions ?? []) {
      if (functions.has(fn.function_id)) pushIssue(issues, "DUPLICATE_FUNCTION_ID", "Duplicate function_id across manifests", { function_id: fn.function_id });
      functions.set(fn.function_id, fn);
      const file = scopeFilesByPath.get(fn.path);
      const functionShapeValid = typeof fn.function_id === "string" && fn.function_id.startsWith("function:")
        && typeof fn.qualified_name === "string" && fn.qualified_name.length > 0
        && Number.isInteger(fn.line_start) && fn.line_start >= 1
        && typeof fn.code_sha256 === "string" && /^[a-f0-9]{64}$/.test(fn.code_sha256);
      if (!file || file.owner_agent !== fn.owner_agent || !exactStringSet(fn.required_lenses, LENSES) || !functionShapeValid || !(manifest.expected_files ?? []).includes(fn.path)) {
        pushIssue(issues, "INVALID_FUNCTION_SCOPE", "Function does not map to its scoped file owner and lenses", { function_id: fn.function_id, path: fn.path });
      }
    }
  }

  for (const file of scopeFiles.values()) {
    if (!file.function_inventory_required) continue;
    const memberships = manifestMembership.get(file.path) ?? [];
    if (memberships.length !== 1) {
      pushIssue(issues, "FUNCTION_FILE_MEMBERSHIP", "Function-bearing file must occur in exactly one inventory manifest", { path: file.path, memberships });
    } else if (PARSER_LANGUAGE.get(file.function_parser) !== memberships[0].language) {
      pushIssue(issues, "FUNCTION_PARSER_MISMATCH", "Function inventory language does not match the scoped parser", {
        path: file.path,
        parser: file.function_parser,
        manifest_language: memberships[0].language,
      });
    }
  }
  for (const path of manifestMembership.keys()) {
    const file = scopeFilesByPath.get(path);
    if (!file?.function_inventory_required) pushIssue(issues, "UNEXPECTED_FUNCTION_FILE", "Function manifest contains an unscoped file", { path });
  }

  const catalogEntries = new Map();
  if (!exactStringSet(catalog.required_lenses, LENSES)) pushIssue(issues, "CATALOG_LENSES_INVALID", "Catalog does not require the three canonical lenses");
  for (const entry of catalog.entries ?? []) {
    if (catalogEntries.has(entry.id)) pushIssue(issues, "DUPLICATE_CATALOG_ID", "Duplicate vulnerability catalog ID", { catalog_id: entry.id });
    catalogEntries.set(entry.id, entry);
    const catalogErrors = [];
    if (typeof entry.id !== "string" || !/^(?:JW|AI)-[A-Z]+-\d{2}$/.test(entry.id)) catalogErrors.push("invalid-id");
    if (typeof entry.title !== "string" || !entry.title) catalogErrors.push("missing-title");
    if (!Array.isArray(entry.applies_to) || entry.applies_to.length === 0 || entry.applies_to.some(domain => !DOMAIN_AGENT.has(domain))) catalogErrors.push("invalid-applies-to");
    if (!Array.isArray(entry.dimensions) || entry.dimensions.length === 0 || entry.dimensions.some(dimension => !DIMENSIONS.includes(dimension))) catalogErrors.push("invalid-dimensions");
    for (const lens of ["sink", "control", "config"]) if (typeof entry[`${lens}_question`] !== "string" || entry[`${lens}_question`].length < 12) catalogErrors.push(`missing-${lens}-question`);
    if (catalogErrors.length > 0) pushIssue(issues, "INVALID_CATALOG_ENTRY", "Catalog entry is incomplete", { catalog_id: entry.id, errors: catalogErrors });
  }

  const activeDomains = new Set(["ai"]);
  for (const file of scopeFiles.values()) {
    for (const [domain, agent] of DOMAIN_AGENT) if (file.owner_agent === agent) activeDomains.add(domain);
  }

  const reports = [];
  const fileRecords = new Map();
  const functionRecords = new Map();
  const catalogRecords = new Map();
  const reportPaths = await listAuditReports(resolve(args["reports-dir"]));
  for (const reportPath of reportPaths) {
    let report;
    try {
      report = JSON.parse(await readFile(reportPath, "utf8"));
    } catch (error) {
      pushIssue(issues, "REPORT_UNREADABLE", error.message, { report: reportPath });
      continue;
    }
    if (report.audit_id !== args["audit-id"]) continue;
    reports.push(reportPath);
    const reportIssues = [];
    if (!Number.isInteger(report.round) || report.round < 1) reportIssues.push("invalid-round");
    if (typeof report.agent_name !== "string" || !report.agent_name) reportIssues.push("missing-agent-name");
    if (typeof report.agent_session_id !== "string" || !report.agent_session_id) reportIssues.push("missing-agent-session-id");
    if (!LENSES.includes(report.audit_strategy)) reportIssues.push("report-must-contain-one-canonical-lens");
    if (!AGENT_LANGUAGE.has(report.agent_name) || report.language !== AGENT_LANGUAGE.get(report.agent_name)) reportIssues.push("agent-language-mismatch");
    if (!exactStringSet(report.dimensions, DIMENSIONS)) reportIssues.push("report-must-cover-D1-through-D10");
    if (!Array.isArray(report.tool_inputs) || report.tool_inputs.length === 0) reportIssues.push("tool-inputs-missing");
    if (report.agent_name === AI_AGENT
      && !report.tool_inputs?.some(input => input?.kind === "ai-surfaces" && input.scope_digest === scope.scope_digest)) {
      reportIssues.push("ai-surfaces-input-missing");
    }
    if (!Array.isArray(report.coverage_cells)) reportIssues.push("coverage-cells-missing");
    if (!Array.isArray(report.findings)) reportIssues.push("findings-missing");
    if (!Array.isArray(report.artifacts)) reportIssues.push("artifacts-missing");
    if (!Array.isArray(report.learning_candidates)) reportIssues.push("learning-candidates-missing");
    if ((report.scope?.scope_digest ?? report.scope_digest) !== scope.scope_digest) reportIssues.push("scope-digest-mismatch");
    if (!Array.isArray(report.scope?.assigned_file_ids) || !Array.isArray(report.scope?.assigned_function_ids) || !Array.isArray(report.scope?.assigned_catalog_ids)) {
      reportIssues.push("assigned-scope-id-arrays-missing");
    }
    if (!Array.isArray(report.file_coverage) || !Array.isArray(report.function_coverage) || !Array.isArray(report.catalog_coverage)) {
      reportIssues.push("coverage-arrays-missing");
    }
    if (reportIssues.length > 0) {
      pushIssue(issues, "INVALID_REPORT", "Audit report does not satisfy the coverage schema", { report: reportPath, errors: reportIssues });
      continue;
    }

    const rawFindingIds = report.findings.map(item => item?.finding_id);
    const findingIds = new Set(rawFindingIds.filter(id => typeof id === "string" && id.length > 0));
    if (findingIds.size !== report.findings.length) {
      pushIssue(issues, "INVALID_FINDINGS", "Every report finding must have a unique non-empty finding_id", { report: reportPath });
    }
    const dimensionValidation = validateDimensionCells(report, catalogEntries);
    if (dimensionValidation.length > 0) {
      pushIssue(issues, "INVALID_DIMENSION_COVERAGE", "D1-D10 coverage cells are incomplete or invalid", { report: reportPath, errors: dimensionValidation });
    }
    const reportedFileIds = report.file_coverage.map(record => record?.file_id);
    const reportedFunctionIds = report.function_coverage.map(record => record?.function_id);
    const reportedCatalogIds = report.catalog_coverage.map(record => record?.catalog_id);
    if (!exactStringSet(report.scope.assigned_file_ids, reportedFileIds)) {
      pushIssue(issues, "REPORT_FILE_ASSIGNMENT_MISMATCH", "file_coverage does not exactly equal scope.assigned_file_ids", { report: reportPath });
    }
    if (!exactStringSet(report.scope.assigned_function_ids, reportedFunctionIds)) {
      pushIssue(issues, "REPORT_FUNCTION_ASSIGNMENT_MISMATCH", "function_coverage does not exactly equal scope.assigned_function_ids", { report: reportPath });
    }
    if (!exactStringSet(report.scope.assigned_catalog_ids, reportedCatalogIds)) {
      pushIssue(issues, "REPORT_CATALOG_ASSIGNMENT_MISMATCH", "catalog_coverage does not exactly equal scope.assigned_catalog_ids", { report: reportPath });
    }
    const seenFileIds = new Set();
    for (const record of report.file_coverage) {
      const id = record?.file_id;
      const domain = record?.domain;
      const file = scopeFiles.get(id);
      if (!file) {
        pushIssue(issues, "UNKNOWN_FILE_COVERAGE", "Report references an unknown file ID", { report: reportPath, file_id: id });
        continue;
      }
      const localKey = `${id}|${domain}`;
      if (seenFileIds.has(localKey)) pushIssue(issues, "DUPLICATE_REPORT_FILE", "Report repeats a file/domain coverage record", { report: reportPath, file_id: id, domain });
      seenFileIds.add(localKey);
      const expectedAgent = domain === "ai" ? AI_AGENT : domain === "base" ? file.owner_agent : null;
      if (!COVERAGE_DOMAINS.includes(domain) || report.agent_name !== expectedAgent) {
        pushIssue(issues, "FILE_OWNER_MISMATCH", "File coverage domain is invalid or not closed by its assigned base/AI owner", { report: reportPath, file_id: id, domain, expected_agent: expectedAgent });
        continue;
      }
      const validation = validateCoverageRecord(record, "file_id", id, DIMENSIONS, findingIds, {
        kind: "file",
        id,
        file,
      });
      const key = `${id}|${domain}|${report.audit_strategy}`;
      const list = fileRecords.get(key) ?? [];
      list.push({ ...record, validation, round: report.round, report_path: reportPath });
      fileRecords.set(key, list);
    }

    const seenFunctionIds = new Set();
    for (const record of report.function_coverage) {
      const id = record?.function_id;
      const domain = record?.domain;
      const fn = functions.get(id);
      if (!fn) {
        pushIssue(issues, "UNKNOWN_FUNCTION_COVERAGE", "Report references an unknown function ID", { report: reportPath, function_id: id });
        continue;
      }
      const localKey = `${id}|${domain}`;
      if (seenFunctionIds.has(localKey)) pushIssue(issues, "DUPLICATE_REPORT_FUNCTION", "Report repeats a function/domain coverage record", { report: reportPath, function_id: id, domain });
      seenFunctionIds.add(localKey);
      const expectedAgent = domain === "ai" ? AI_AGENT : domain === "base" ? fn.owner_agent : null;
      if (!COVERAGE_DOMAINS.includes(domain) || report.agent_name !== expectedAgent) {
        pushIssue(issues, "FUNCTION_OWNER_MISMATCH", "Function coverage domain is invalid or not closed by its assigned base/AI owner", { report: reportPath, function_id: id, domain, expected_agent: expectedAgent });
        continue;
      }
      const validation = validateCoverageRecord(record, "function_id", id, DIMENSIONS, findingIds, {
        kind: "function",
        id,
        fn,
      });
      const key = `${id}|${domain}|${report.audit_strategy}`;
      const list = functionRecords.get(key) ?? [];
      list.push({ ...record, validation, round: report.round, report_path: reportPath });
      functionRecords.set(key, list);
    }

    const seenCatalogKeys = new Set();
    for (const record of report.catalog_coverage) {
      const id = record?.catalog_id;
      const entry = catalogEntries.get(id);
      if (!entry) {
        pushIssue(issues, "UNKNOWN_CATALOG_COVERAGE", "Report references an unknown catalog ID", { report: reportPath, catalog_id: id });
        continue;
      }
      const domain = record.domain;
      const localKey = `${id}|${domain}`;
      if (seenCatalogKeys.has(localKey)) pushIssue(issues, "DUPLICATE_REPORT_CATALOG", "Report repeats a catalog/domain coverage record", { report: reportPath, catalog_id: id, domain });
      seenCatalogKeys.add(localKey);
      if (!DOMAIN_AGENT.has(domain) || DOMAIN_AGENT.get(domain) !== report.agent_name || !activeDomains.has(domain) || !entry.applies_to.includes(domain)) {
        pushIssue(issues, "CATALOG_DOMAIN_MISMATCH", "Catalog coverage is not owned by an active applicable domain agent", { report: reportPath, catalog_id: id, domain });
        continue;
      }
      const validation = validateCoverageRecord(record, "catalog_id", id, entry.dimensions, findingIds, {
        kind: "catalog",
        id,
        entry,
        domain,
        lens: report.audit_strategy,
        catalog,
      });
      const key = `${id}|${domain}|${report.audit_strategy}`;
      const list = catalogRecords.get(key) ?? [];
      list.push({ ...record, validation, round: report.round, report_path: reportPath });
      catalogRecords.set(key, list);
    }
  }

  if (reports.length === 0) pushIssue(issues, "NO_AUDIT_REPORTS", "No report for the requested audit_id was found");

  const missing = { files: [], functions: [], catalog: [] };
  const invalid = { files: [], functions: [], catalog: [] };
  for (const file of scopeFiles.values()) {
    if (!file.review_required) continue;
    for (const domain of COVERAGE_DOMAINS) {
      for (const lens of LENSES) {
        const key = `${file.file_id}|${domain}|${lens}`;
        const latest = selectLatest(fileRecords.get(key) ?? [], key, issues);
        const ownerAgent = domain === "ai" ? AI_AGENT : file.owner_agent;
        if (!latest) missing.files.push({ file_id: file.file_id, path: file.path, domain, owner_agent: ownerAgent, lens });
        else if (latest.validation.length > 0 || !CLOSED_STATUSES.has(latest.status)) invalid.files.push({ file_id: file.file_id, path: file.path, domain, lens, errors: latest.validation, report: latest.report_path });
      }
    }
  }
  for (const fn of functions.values()) {
    for (const domain of COVERAGE_DOMAINS) {
      for (const lens of LENSES) {
        const key = `${fn.function_id}|${domain}|${lens}`;
        const latest = selectLatest(functionRecords.get(key) ?? [], key, issues);
        const ownerAgent = domain === "ai" ? AI_AGENT : fn.owner_agent;
        if (!latest) missing.functions.push({ function_id: fn.function_id, path: fn.path, qualified_name: fn.qualified_name, domain, owner_agent: ownerAgent, lens });
        else if (latest.validation.length > 0 || !CLOSED_STATUSES.has(latest.status)) invalid.functions.push({ function_id: fn.function_id, path: fn.path, qualified_name: fn.qualified_name, domain, lens, errors: latest.validation, report: latest.report_path });
      }
    }
  }
  for (const entry of catalogEntries.values()) {
    for (const domain of entry.applies_to.filter(item => activeDomains.has(item))) {
      for (const lens of LENSES) {
        const key = `${entry.id}|${domain}|${lens}`;
        const latest = selectLatest(catalogRecords.get(key) ?? [], key, issues);
        if (!latest) missing.catalog.push({ catalog_id: entry.id, title: entry.title, domain, owner_agent: DOMAIN_AGENT.get(domain), lens });
        else if (latest.validation.length > 0 || !CLOSED_STATUSES.has(latest.status)) invalid.catalog.push({ catalog_id: entry.id, title: entry.title, domain, lens, errors: latest.validation, report: latest.report_path });
      }
    }
  }

  const complete = issues.length === 0
    && missing.files.length === 0 && missing.functions.length === 0 && missing.catalog.length === 0
    && invalid.files.length === 0 && invalid.functions.length === 0 && invalid.catalog.length === 0;
  const verification = {
    schema_version: 1,
    audit_id: args["audit-id"],
    scope_digest: scope.scope_digest,
    catalog_profile: catalog.profile_id,
    required_lenses: LENSES,
    active_domains: [...activeDomains].sort(),
    inputs: {
      root,
      scope_manifest: resolve(args.scope),
      snapshot_index: snapshotIndexPath,
      function_manifests: functionManifests.map(item => item.path),
      reports_directory: resolve(args["reports-dir"]),
      reports,
      catalog: resolve(args.catalog),
      interfaces: resolve(args.interfaces),
      interface_extractors: resolve(args["interface-extractors"]),
    },
    expected: {
      files: [...scopeFiles.values()].filter(file => file.review_required).length,
      functions: functions.size,
      file_function_coverage_domains: COVERAGE_DOMAINS,
      file_domain_pairs: [...scopeFiles.values()].filter(file => file.review_required).length * COVERAGE_DOMAINS.length,
      function_domain_pairs: functions.size * COVERAGE_DOMAINS.length,
      catalog_domain_pairs: [...catalogEntries.values()].reduce((sum, entry) => sum + entry.applies_to.filter(domain => activeDomains.has(domain)).length, 0),
      external_interfaces: interfaceManifest?.interfaces?.length ?? 0,
      confirmed_external_interfaces: interfaceManifest?.interfaces?.filter(item => item.discovery_state === "CONFIRMED").length ?? 0,
      candidate_external_interfaces: interfaceManifest?.interfaces?.filter(item => item.discovery_state === "CANDIDATE").length ?? 0,
      interface_extractor_files: interfaceManifest?.file_coverage?.length ?? 0,
      lenses_per_item: LENSES.length,
    },
    observed_record_keys: {
      files: fileRecords.size,
      functions: functionRecords.size,
      catalog: catalogRecords.size,
    },
    missing,
    invalid,
    issues,
    current_scope_digest: currentScope?.scope_digest ?? null,
    complete,
    interface_extractor_verification: interfaceExtractorCoverage ? {
      manifest_digest: interfaceExtractorCoverage.manifest_digest,
      complete: interfaceExtractorCoverage.complete,
      interfaces: interfaceExtractorCoverage.interfaces,
    } : null,
    claim_boundary: "Proves deterministic base-owner and AI-overlay accounting over frozen files, source-defined functions and executable template units recognized by configured AST/CPG extractors, the application/platform/AI catalog matrix, and exact source/spec/config interface-anchor enumeration by configured extractors. CONFIRMED and CANDIDATE interface counts are reported separately. Unsupported or dynamic interface sources prevent completion. This phase does not yet prove that each interface received every applicable vulnerability-type check.",
  };
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(verification, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: outputPath, complete, expected: verification.expected, missing: { files: missing.files.length, functions: missing.functions.length, catalog: missing.catalog.length }, invalid: { files: invalid.files.length, functions: invalid.functions.length, catalog: invalid.catalog.length }, issues: issues.length })}\n`);
  if (!complete) process.exitCode = 2;
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
