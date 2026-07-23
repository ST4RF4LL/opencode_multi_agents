#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { contentDigest } from "./function-manifest-cache.mjs";

const INDEX_VERSION = 1;

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
  for (const key of ["audit-id", "scope", "catalog", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
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
  if (typeof catalog.profile_id !== "string" || !Array.isArray(catalog.entries)) throw new Error("Catalog is incomplete");
  const routes = (scope.files ?? []).filter(file => file.review_required).map(file => ({
    file_id: file.file_id,
    path: file.path,
    owner_agent: file.owner_agent,
    content_kind: file.content_kind,
    functions: (functionsByPath.get(file.path) ?? []).sort((a, b) => a.line_start - b.line_start || a.function_id.localeCompare(b.function_id)),
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
      catalog: { path: catalogPath, profile_id: catalog.profile_id },
    },
    routes,
    catalog: catalog.entries.map(entry => ({
      catalog_id: entry.id,
      title: entry.title,
      applies_to: entry.applies_to,
      dimensions: entry.dimensions,
    })),
    summary: {
      files: routes.length,
      functions: routes.reduce((sum, route) => sum + route.functions.length, 0),
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
