#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const LENSES = ["sink-driven", "control-driven", "config-driven"];
const FILE_STATES = new Set(["INSPECTED", "NOT_APPLICABLE", "INDETERMINATE", "FAILED"]);
const INTERFACE_STATES = new Set(["CONFIRMED", "CANDIDATE"]);
const DIRECTIONS = new Set(["ingress", "egress", "bidirectional"]);

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["audit-id", "scope", "interfaces", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function objectDigest(value) {
  const copy = { ...value };
  delete copy.manifest_digest;
  return digest(JSON.stringify(copy));
}

function exactSet(left, right) {
  return Array.isArray(left) && Array.isArray(right)
    && left.length === right.length && new Set(left).size === left.length
    && left.every(item => right.includes(item));
}

function issue(issues, code, message, details = {}) {
  issues.push({ code, message, ...details });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const outputPath = resolve(args.output);
  const [scope, manifest] = await Promise.all([
    readFile(resolve(args.scope), "utf8").then(JSON.parse),
    readFile(resolve(args.interfaces), "utf8").then(JSON.parse),
  ]);
  const issues = [];
  if (scope.audit_id !== args["audit-id"] || !scope.complete || scope.manifest_digest !== objectDigest(scope)) issue(issues, "SCOPE_INVALID", "Scope manifest is incomplete, modified, or bound to another audit");
  if (manifest.audit_id !== args["audit-id"] || manifest.scope_digest !== scope.scope_digest || manifest.manifest_digest !== objectDigest(manifest)) issue(issues, "INTERFACE_MANIFEST_INVALID", "Interface manifest is modified or scope-mismatched");
  if (!exactSet(manifest.required_lenses, LENSES)) issue(issues, "INTERFACE_LENSES_INVALID", "Interface manifest does not require all three lenses");

  const files = new Map((scope.files ?? []).filter(file => file.review_required).map(file => [file.file_id, file]));
  const coverageRows = new Map();
  for (const row of manifest.file_coverage ?? []) {
    if (coverageRows.has(row.file_id)) issue(issues, "DUPLICATE_FILE_COVERAGE", "Interface manifest repeats file coverage", { file_id: row.file_id });
    coverageRows.set(row.file_id, row);
    const file = files.get(row.file_id);
    if (!file || row.path !== file.path || row.source_sha256 !== (file.sha256 ?? null)) issue(issues, "FILE_COVERAGE_SCOPE_MISMATCH", "Interface file coverage is not bound to frozen source", { file_id: row.file_id });
    if (!FILE_STATES.has(row.state)) issue(issues, "FILE_COVERAGE_STATE_INVALID", "Interface file coverage has an invalid state", { file_id: row.file_id, state: row.state });
    if (!Array.isArray(row.extractor_ids) || !Array.isArray(row.interface_ids) || !Array.isArray(row.gaps)) issue(issues, "FILE_COVERAGE_SHAPE_INVALID", "Interface file coverage arrays are missing", { file_id: row.file_id });
    if (["INDETERMINATE", "FAILED"].includes(row.state)) issue(issues, "INTERFACE_EXTRACTION_GAP", "Potential interface source was not deterministically inventoried", { file_id: row.file_id, path: row.path, state: row.state, reason: row.reason });
  }
  for (const file of files.values()) if (!coverageRows.has(file.file_id)) issue(issues, "MISSING_FILE_COVERAGE", "Scoped file lacks interface extractor coverage", { file_id: file.file_id, path: file.path });
  for (const id of coverageRows.keys()) if (!files.has(id)) issue(issues, "UNKNOWN_FILE_COVERAGE", "Interface extractor coverage references an unknown file", { file_id: id });

  const interfaces = new Map();
  for (const item of manifest.interfaces ?? []) {
    if (interfaces.has(item.interface_id)) issue(issues, "DUPLICATE_INTERFACE_ID", "Interface manifest repeats interface_id", { interface_id: item.interface_id });
    interfaces.set(item.interface_id, item);
    const file = files.get(item.file_id);
    const row = coverageRows.get(item.file_id);
    if (!file || item.path !== file.path || item.owner_agent !== file.owner_agent || !row?.interface_ids?.includes(item.interface_id)) {
      issue(issues, "INTERFACE_SCOPE_MISMATCH", "Interface is not bound to a scoped file and extractor row", { interface_id: item.interface_id });
    }
    if (!INTERFACE_STATES.has(item.discovery_state) || !DIRECTIONS.has(item.direction) || !exactSet(item.required_lenses, LENSES)
      || !Array.isArray(item.dimensions) || item.dimensions.length === 0 || !item.dimensions.every(value => /^D(?:10|[1-9])$/.test(value))
      || !Number.isInteger(item.line_start) || item.line_start < 1 || typeof item.address !== "string" || !item.address) {
      issue(issues, "INTERFACE_SHAPE_INVALID", "Interface record has invalid state, direction, dimensions, location, or address", { interface_id: item.interface_id });
    }
    if (!Array.isArray(item.evidence) || item.evidence.length !== 1) {
      issue(issues, "INTERFACE_EVIDENCE_INVALID", "Interface must contain one extractor evidence anchor", { interface_id: item.interface_id });
    } else {
      const evidence = item.evidence[0];
      if (evidence.kind !== "interface-source-anchor" || evidence.file_id !== item.file_id || evidence.path !== item.path
        || evidence.source_sha256 !== file?.sha256 || evidence.line_start !== item.line_start
        || !manifest.extractor_ids?.includes(evidence.extractor_id) || !/^[a-f0-9]{64}$/.test(evidence.match_sha256 ?? "")) {
        issue(issues, "INTERFACE_EVIDENCE_NOT_BOUND", "Interface evidence is not bound to its frozen source and extractor", { interface_id: item.interface_id });
      }
    }
  }
  for (const row of coverageRows.values()) {
    if (new Set(row.interface_ids ?? []).size !== (row.interface_ids ?? []).length) issue(issues, "DUPLICATE_FILE_INTERFACE_ID", "File extractor row repeats an interface ID", { file_id: row.file_id });
    for (const interfaceId of row.interface_ids ?? []) if (!interfaces.has(interfaceId)) issue(issues, "UNKNOWN_FILE_INTERFACE_ID", "File extractor row references an unknown interface", { file_id: row.file_id, interface_id: interfaceId });
  }
  if ((manifest.gaps?.length ?? 0) > 0 || manifest.complete !== true) issue(issues, "INTERFACE_MANIFEST_INCOMPLETE", "Interface manifest contains extraction gaps");

  const verification = {
    schema_version: 1,
    audit_id: args["audit-id"],
    scope_digest: scope.scope_digest,
    interface_manifest_digest: manifest.manifest_digest ?? null,
    expected_files: files.size,
    observed_files: coverageRows.size,
    interfaces: {
      total: interfaces.size,
      confirmed: [...interfaces.values()].filter(item => item.discovery_state === "CONFIRMED").length,
      candidate: [...interfaces.values()].filter(item => item.discovery_state === "CANDIDATE").length,
      ingress: [...interfaces.values()].filter(item => item.direction === "ingress").length,
      egress: [...interfaces.values()].filter(item => item.direction === "egress").length,
      bidirectional: [...interfaces.values()].filter(item => item.direction === "bidirectional").length,
    },
    issues,
    complete: issues.length === 0,
    claim_boundary: "Proves exact accounting and frozen-source binding for the configured interface extractors. It does not turn CANDIDATE anchors into confirmed deployed endpoints and cannot cover runtime-only interfaces absent from source/spec/config evidence.",
  };
  verification.manifest_digest = objectDigest(verification);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(verification, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: outputPath, complete: verification.complete, expected_files: files.size, observed_files: coverageRows.size, interfaces: verification.interfaces, issues: issues.length, manifest_digest: verification.manifest_digest })}\n`);
  if (!verification.complete) process.exitCode = 2;
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
