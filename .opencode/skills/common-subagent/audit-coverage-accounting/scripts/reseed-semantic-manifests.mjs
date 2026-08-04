#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { objectDigest } from "./coverage-v2-common.mjs";
import { validateThreatModel } from "../../../threat-modeling-subagent/evidence-backed-threat-modeling/scripts/threat-model-contract.mjs";

const REGENERABLE_CACHE_PREFIXES = [".atlas/"];

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["audit-id", "scope", "source-scope", "source-threat-model", "source-focus-areas", "threat-output", "focus-output"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  }
  return args;
}

function semanticDigest(value) {
  const copy = structuredClone(value);
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

function validDigest(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function sourceMap(scope, allowRegenerableCaches) {
  const entries = (scope.files ?? []).filter(file => !(allowRegenerableCaches
    && REGENERABLE_CACHE_PREFIXES.some(prefix => file.path?.startsWith(prefix))));
  if (entries.some(file => typeof file.path !== "string" || !validDigest(file.sha256))) {
    throw new Error("Scope contains an invalid source path or digest");
  }
  return new Map(entries.map(file => [file.path, file.sha256]));
}

function sameSources(sourceScope, targetScope) {
  const source = sourceMap(sourceScope, true);
  const target = sourceMap(targetScope, false);
  return source.size === target.size && [...source].every(([path, digest]) => target.get(path) === digest);
}

function validateScope(scope, expectedAuditId) {
  if (scope?.schema_version !== 1 || scope.audit_id !== expectedAuditId || scope.complete !== true
    || !validDigest(scope.scope_digest) || scope.manifest_digest !== objectDigest(scope)) {
    throw new Error("Scope manifest is incomplete, modified, or bound to another audit");
  }
}

function validateSemanticSource(threatModel, focusAreas, sourceScope) {
  const threatErrors = validateThreatModel(threatModel, {
    auditId: sourceScope.audit_id,
    scopeDigest: sourceScope.scope_digest,
  });
  if (threatErrors.length > 0) {
    throw new Error("Source threat model is invalid or not bound to the source scope");
  }
  if (focusAreas?.schema_version !== 1 || focusAreas.audit_id !== sourceScope.audit_id
    || focusAreas.scope_digest !== sourceScope.scope_digest || focusAreas.threat_model_digest !== threatModel.manifest_digest
    || !Array.isArray(focusAreas.required_lenses) || !Array.isArray(focusAreas.focus_areas)
    || focusAreas.manifest_digest !== semanticDigest(focusAreas)) {
    throw new Error("Source Focus Area manifest is invalid or not bound to the source threat model");
  }
}

function reseedThreatModel(source, auditId, scopeDigest) {
  const output = structuredClone(source);
  output.audit_id = auditId;
  output.scope_digest = scopeDigest;
  output.carry_forward = {
    source_audit_id: source.audit_id,
    source_scope_digest: source.scope_digest,
    source_manifest_digest: source.manifest_digest,
    source_equivalence: "all non-cache frozen file paths and hashes match",
    revalidation_required: true,
    restrictions: "This transfers recon hypotheses and partitioning only; it never transfers coverage, Ledger decisions, Finding states, adjudications, chains, or final report conclusions.",
  };
  delete output.manifest_digest;
  output.manifest_digest = semanticDigest(output);
  const errors = validateThreatModel(output, { auditId, scopeDigest });
  if (errors.length > 0) throw new Error(`Reseeded threat model is invalid: ${errors.join(", ")}`);
  return output;
}

function reseedFocusAreas(source, sourceScope, auditId, scopeDigest, threatModel) {
  const output = structuredClone(source);
  const excludedFileIds = new Set((sourceScope.files ?? [])
    .filter(file => REGENERABLE_CACHE_PREFIXES.some(prefix => file.path?.startsWith(prefix)))
    .map(file => file.file_id));
  for (const focusArea of output.focus_areas ?? []) {
    focusArea.context_file_ids = (focusArea.context_file_ids ?? []).filter(id => !excludedFileIds.has(id));
    for (const assignment of focusArea.assignments ?? []) {
      assignment.file_ids = (assignment.file_ids ?? []).filter(id => !excludedFileIds.has(id));
    }
  }
  output.audit_id = auditId;
  output.scope_digest = scopeDigest;
  output.threat_model_digest = threatModel.manifest_digest;
  output.carry_forward = {
    source_audit_id: source.audit_id,
    source_scope_digest: source.scope_digest,
    source_manifest_digest: source.manifest_digest,
    revalidation_required: true,
    pruned_regenerable_cache_file_ids: [...excludedFileIds].sort(),
  };
  delete output.manifest_digest;
  output.manifest_digest = semanticDigest(output);
  return output;
}

async function writeJson(path, value) {
  const output = resolve(path);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [scope, sourceScope, sourceThreatModel, sourceFocusAreas] = await Promise.all([
    readFile(resolve(args.scope), "utf8").then(JSON.parse),
    readFile(resolve(args["source-scope"]), "utf8").then(JSON.parse),
    readFile(resolve(args["source-threat-model"]), "utf8").then(JSON.parse),
    readFile(resolve(args["source-focus-areas"]), "utf8").then(JSON.parse),
  ]);
  validateScope(scope, args["audit-id"]);
  validateScope(sourceScope, sourceScope.audit_id);
  validateSemanticSource(sourceThreatModel, sourceFocusAreas, sourceScope);
  if (!sameSources(sourceScope, scope)) {
    throw new Error("Cannot carry forward semantic hypotheses: frozen non-cache sources differ");
  }
  const threatModel = reseedThreatModel(sourceThreatModel, args["audit-id"], scope.scope_digest);
  const focusAreas = reseedFocusAreas(sourceFocusAreas, sourceScope, args["audit-id"], scope.scope_digest, threatModel);
  await Promise.all([writeJson(args["threat-output"], threatModel), writeJson(args["focus-output"], focusAreas)]);
  process.stdout.write(`${JSON.stringify({
    audit_id: args["audit-id"],
    source_audit_id: sourceScope.audit_id,
    scope_digest: scope.scope_digest,
    threat_model_digest: threatModel.manifest_digest,
    focus_areas_digest: focusAreas.manifest_digest,
    carried_threats: threatModel.threats.length,
    carried_focus_areas: focusAreas.focus_areas.length,
    revalidation_required: true,
  })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
