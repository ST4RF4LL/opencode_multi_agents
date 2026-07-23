#!/usr/bin/env node

import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { validateCatalogV2 } from "./coverage-v2-common.mjs";

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
  for (const key of ["audit-id", "scope", "interfaces", "interface-extractors", "catalog", "output-dir"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  if (args.functions.length === 0) throw new Error("At least one --functions manifest is required");
  if (Boolean(args["threat-model"]) !== Boolean(args["focus-areas"])) throw new Error("--threat-model and --focus-areas must be provided together");
  return args;
}

function objectDigest(value) {
  const copy = { ...value };
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

function bytesDigest(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const outputDir = resolve(args["output-dir"]);
  await mkdir(outputDir, { recursive: true });

  const scopeSource = resolve(args.scope);
  const scopeBytes = await readFile(scopeSource);
  const scope = JSON.parse(scopeBytes.toString("utf8"));
  if (scope.audit_id !== args["audit-id"] || !scope.complete || scope.manifest_digest !== objectDigest(scope)) {
    throw new Error("Cannot snapshot an incomplete, modified, or wrong-audit scope manifest");
  }
  const scopeTarget = join(outputDir, "scope-manifest.json");
  await copyFile(scopeSource, scopeTarget);

  const functionSnapshots = [];
  const languages = new Set();
  for (const input of args.functions) {
    const source = resolve(input);
    const bytes = await readFile(source);
    const manifest = JSON.parse(bytes.toString("utf8"));
    if (manifest.audit_id !== args["audit-id"] || manifest.scope_digest !== scope.scope_digest || !manifest.complete || manifest.manifest_digest !== objectDigest(manifest)) {
      throw new Error(`Cannot snapshot incomplete, modified, or scope-mismatched function manifest: ${source}`);
    }
    if (languages.has(manifest.language)) throw new Error(`Duplicate function manifest language: ${manifest.language}`);
    languages.add(manifest.language);
    const target = join(outputDir, `functions-${manifest.language}.json`);
    await copyFile(source, target);
    functionSnapshots.push({
      language: manifest.language,
      path: target,
      file_name: basename(target),
      manifest_digest: manifest.manifest_digest,
      sha256: bytesDigest(bytes),
      expected_files: manifest.expected_files.length,
      functions: manifest.functions.length,
    });
  }

  const catalogSource = resolve(args.catalog);
  const catalogBytes = await readFile(catalogSource);
  const catalog = JSON.parse(catalogBytes.toString("utf8"));
  const catalogErrors = validateCatalogV2(catalog);
  if (catalogErrors.length > 0) throw new Error(`Cannot snapshot invalid catalog v2:\n- ${catalogErrors.join("\n- ")}`);
  const catalogTarget = join(outputDir, "application-ai-vulnerability-catalog.json");
  await copyFile(catalogSource, catalogTarget);

  const interfaceSource = resolve(args.interfaces);
  const interfaceBytes = await readFile(interfaceSource);
  const interfaceManifest = JSON.parse(interfaceBytes.toString("utf8"));
  if (interfaceManifest.audit_id !== args["audit-id"] || interfaceManifest.scope_digest !== scope.scope_digest
    || interfaceManifest.manifest_digest !== objectDigest(interfaceManifest)) {
    throw new Error("Cannot snapshot a modified or scope-mismatched interface manifest");
  }
  const interfaceTarget = join(outputDir, "interface-manifest.json");
  await copyFile(interfaceSource, interfaceTarget);

  const extractorSource = resolve(args["interface-extractors"]);
  const extractorBytes = await readFile(extractorSource);
  const extractorCoverage = JSON.parse(extractorBytes.toString("utf8"));
  if (extractorCoverage.audit_id !== args["audit-id"] || extractorCoverage.scope_digest !== scope.scope_digest
    || extractorCoverage.interface_manifest_digest !== interfaceManifest.manifest_digest
    || extractorCoverage.manifest_digest !== objectDigest(extractorCoverage) || !extractorCoverage.complete) {
    throw new Error("Cannot snapshot incomplete, modified, or interface-mismatched extractor verification");
  }
  const extractorTarget = join(outputDir, "interface-extractor-coverage.json");
  await copyFile(extractorSource, extractorTarget);

  let semantic = null;
  if (args["threat-model"] && args["focus-areas"]) {
    const threatSource = resolve(args["threat-model"]);
    const focusSource = resolve(args["focus-areas"]);
    const threatBytes = await readFile(threatSource);
    const focusBytes = await readFile(focusSource);
    const threat = JSON.parse(threatBytes.toString("utf8"));
    const focus = JSON.parse(focusBytes.toString("utf8"));
    if (threat.audit_id !== args["audit-id"] || threat.scope_digest !== scope.scope_digest || threat.manifest_digest !== objectDigest(threat)) {
      throw new Error("Cannot snapshot an incomplete, modified, or scope-mismatched threat model");
    }
    if (focus.audit_id !== args["audit-id"] || focus.scope_digest !== scope.scope_digest || focus.manifest_digest !== objectDigest(focus)
      || focus.threat_model_digest !== threat.manifest_digest) {
      throw new Error("Cannot snapshot incomplete, modified, or threat-model-mismatched Focus Areas");
    }
    const threatTarget = join(outputDir, "threat-model.json");
    const focusTarget = join(outputDir, "focus-areas.json");
    await copyFile(threatSource, threatTarget);
    await copyFile(focusSource, focusTarget);
    semantic = {
      threat_model: { path: threatTarget, file_name: basename(threatTarget), manifest_digest: threat.manifest_digest, sha256: bytesDigest(threatBytes), entry_points: threat.entry_points?.length ?? 0, threats: threat.threats?.length ?? 0 },
      focus_areas: { path: focusTarget, file_name: basename(focusTarget), manifest_digest: focus.manifest_digest, sha256: bytesDigest(focusBytes), focus_areas: focus.focus_areas?.length ?? 0 },
    };
  }

  const index = {
    schema_version: 1,
    audit_id: args["audit-id"],
    scope_digest: scope.scope_digest,
    scope: { path: scopeTarget, file_name: basename(scopeTarget), manifest_digest: scope.manifest_digest, sha256: bytesDigest(scopeBytes), files: scope.files.length },
    functions: functionSnapshots.sort((a, b) => a.language.localeCompare(b.language)),
    interfaces: {
      path: interfaceTarget,
      file_name: basename(interfaceTarget),
      manifest_digest: interfaceManifest.manifest_digest,
      sha256: bytesDigest(interfaceBytes),
      total: interfaceManifest.interfaces.length,
      confirmed: interfaceManifest.interfaces.filter(item => item.discovery_state === "CONFIRMED").length,
      candidate: interfaceManifest.interfaces.filter(item => item.discovery_state === "CANDIDATE").length,
    },
    interface_extractors: {
      path: extractorTarget,
      file_name: basename(extractorTarget),
      manifest_digest: extractorCoverage.manifest_digest,
      sha256: bytesDigest(extractorBytes),
      complete: extractorCoverage.complete,
    },
    catalog: { path: catalogTarget, file_name: basename(catalogTarget), profile_id: catalog.profile_id, sha256: bytesDigest(catalogBytes), entries: catalog.entries.length },
    ...(semantic ? { semantic } : {}),
  };
  index.snapshot_digest = createHash("sha256").update(JSON.stringify(index)).digest("hex");
  const indexPath = join(outputDir, "snapshot-index.json");
  await writeFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: indexPath, audit_id: index.audit_id, scope_files: index.scope.files, function_manifests: index.functions.length, functions: index.functions.reduce((sum, item) => sum + item.functions, 0), interfaces: index.interfaces, interface_extractors_complete: index.interface_extractors.complete, catalog_entries: index.catalog.entries, semantic: semantic ? { entry_points: semantic.threat_model.entry_points, threats: semantic.threat_model.threats, focus_areas: semantic.focus_areas.focus_areas } : null, snapshot_digest: index.snapshot_digest })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
