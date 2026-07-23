#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { contentDigest } from "./function-manifest-cache.mjs";
import { entryAppliesToDomain, validateCatalogV2 } from "./coverage-v2-common.mjs";

const INDEX_VERSION = 2;

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
  for (const key of ["audit-id", "scope", "interfaces", "interface-extractors", "catalog", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  if (args.functions.length === 0) throw new Error("At least one --functions manifest is required");
  return args;
}

function indexDigest(value) {
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
  if (scope.audit_id !== args["audit-id"] || !scope.complete || scope.manifest_digest !== contentDigest(scope)) {
    throw new Error("Scope manifest is incomplete, modified, or bound to another audit");
  }

  const manifests = [];
  const functionsByPath = new Map();
  const membership = new Map();
  const languages = new Set();
  const functionIds = new Set();
  for (const input of args.functions) {
    const path = resolve(input);
    const manifest = JSON.parse(await readFile(path, "utf8"));
    if (manifest.audit_id !== args["audit-id"] || manifest.scope_digest !== scope.scope_digest
      || !manifest.complete || manifest.manifest_digest !== contentDigest(manifest)) {
      throw new Error(`Function manifest is incomplete, modified, or scope-mismatched: ${path}`);
    }
    if (languages.has(manifest.language)) throw new Error(`Duplicate function manifest language: ${manifest.language}`);
    languages.add(manifest.language);
    manifests.push({ language: manifest.language, path, manifest_digest: manifest.manifest_digest });
    for (const file of manifest.expected_files ?? []) membership.set(file, (membership.get(file) ?? 0) + 1);
    for (const fn of manifest.functions ?? []) {
      if (functionIds.has(fn.function_id)) throw new Error(`Duplicate function ID across manifests: ${fn.function_id}`);
      functionIds.add(fn.function_id);
      const rows = functionsByPath.get(fn.path) ?? [];
      rows.push({ function_id: fn.function_id, name: fn.name, kind: fn.kind, line_start: fn.line_start });
      functionsByPath.set(fn.path, rows);
    }
  }
  const missing = (scope.files ?? []).filter(file => file.function_inventory_required && membership.get(file.path) !== 1);
  if (missing.length > 0) throw new Error(`Function manifest membership is incomplete for ${missing.map(file => file.path).join(", ")}`);

  const catalog = JSON.parse(await readFile(catalogPath, "utf8"));
  const catalogErrors = validateCatalogV2(catalog);
  if (catalogErrors.length > 0) throw new Error(`Catalog v2 is invalid:\n- ${catalogErrors.join("\n- ")}`);
  const catalogDomains = Object.keys(catalog.coverage_model.domain_profiles).sort();
  const interfacePath = resolve(args.interfaces);
  const interfaceExtractorPath = resolve(args["interface-extractors"]);
  const interfaceManifest = JSON.parse(await readFile(interfacePath, "utf8"));
  const interfaceExtractors = JSON.parse(await readFile(interfaceExtractorPath, "utf8"));
  if (interfaceManifest.audit_id !== args["audit-id"] || interfaceManifest.scope_digest !== scope.scope_digest
    || interfaceManifest.manifest_digest !== contentDigest(interfaceManifest)
    || interfaceExtractors.audit_id !== args["audit-id"] || interfaceExtractors.scope_digest !== scope.scope_digest
    || interfaceExtractors.interface_manifest_digest !== interfaceManifest.manifest_digest
    || interfaceExtractors.manifest_digest !== contentDigest(interfaceExtractors) || !interfaceExtractors.complete) {
    throw new Error("Interface inventory or extractor verification is incomplete, modified, or scope-mismatched");
  }
  const interfacesByPath = new Map();
  for (const item of interfaceManifest.interfaces ?? []) {
    const rows = interfacesByPath.get(item.path) ?? [];
    rows.push({
      interface_id: item.interface_id,
      discovery_state: item.discovery_state,
      direction: item.direction,
      kind: item.kind,
      protocol: item.protocol,
      operation: item.operation,
      address: item.address,
      line_start: item.line_start,
      dimensions: item.dimensions,
    });
    interfacesByPath.set(item.path, rows);
  }
  const routes = (scope.files ?? []).filter(file => file.review_required).map(file => ({
    file_id: file.file_id,
    path: file.path,
    owner_agent: file.owner_agent,
    content_kind: file.content_kind,
    functions: (functionsByPath.get(file.path) ?? []).sort((a, b) => a.line_start - b.line_start || a.function_id.localeCompare(b.function_id)),
    interfaces: (interfacesByPath.get(file.path) ?? []).sort((a, b) => a.line_start - b.line_start || a.interface_id.localeCompare(b.interface_id)),
  }));
  const index = {
    schema_version: 1,
    index_version: INDEX_VERSION,
    audit_id: args["audit-id"],
    scope_digest: scope.scope_digest,
    required_lenses: scope.policy?.lenses ?? [],
    coverage_domains: ["base", "ai"],
    inputs: {
      scope: { path: scopePath, manifest_digest: scope.manifest_digest },
      functions: manifests.sort((a, b) => a.language.localeCompare(b.language)),
      interfaces: { path: interfacePath, manifest_digest: interfaceManifest.manifest_digest },
      interface_extractors: { path: interfaceExtractorPath, manifest_digest: interfaceExtractors.manifest_digest },
      catalog: { path: catalogPath, profile_id: catalog.profile_id },
    },
    routes,
    catalog: catalog.entries.map(entry => ({
      catalog_id: entry.id,
      title: entry.title,
      applies_to: entry.applies_to,
      effective_domains: catalogDomains.filter(domain => entryAppliesToDomain(entry, domain, catalog)),
      dimensions: entry.dimensions,
    })),
    summary: {
      files: routes.length,
      functions: routes.reduce((sum, route) => sum + route.functions.length, 0),
      interfaces: interfaceManifest.interfaces.length,
      confirmed_interfaces: interfaceManifest.interfaces.filter(item => item.discovery_state === "CONFIRMED").length,
      candidate_interfaces: interfaceManifest.interfaces.filter(item => item.discovery_state === "CANDIDATE").length,
      catalog_entries: catalog.entries.length,
    },
  };
  index.manifest_digest = indexDigest(index);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(index)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: outputPath, ...index.summary, manifest_digest: index.manifest_digest })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
