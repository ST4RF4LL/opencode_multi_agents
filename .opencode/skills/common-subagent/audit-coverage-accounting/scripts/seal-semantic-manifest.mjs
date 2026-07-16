#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  if (!args.input) throw new Error("Required argument missing: --input");
  return args;
}

function manifestDigest(value) {
  const copy = { ...value };
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const inputPath = resolve(args.input);
  const outputPath = resolve(args.output ?? args.input);
  const manifest = JSON.parse(await readFile(inputPath, "utf8"));
  if (manifest.schema_version !== 1) throw new Error("Semantic manifest must use schema_version=1");
  if (typeof manifest.audit_id !== "string" || manifest.audit_id.length < 3) throw new Error("Semantic manifest lacks audit_id");
  if (typeof manifest.scope_digest !== "string" || !/^[a-f0-9]{64}$/.test(manifest.scope_digest)) throw new Error("Semantic manifest lacks a valid scope_digest");
  const isThreatModel = Array.isArray(manifest.entry_points) && Array.isArray(manifest.threats);
  const isFocusAreas = Array.isArray(manifest.focus_areas) && Array.isArray(manifest.required_lenses);
  if (!isThreatModel && !isFocusAreas) throw new Error("Input is neither a threat model nor a Focus Area manifest");
  if (isFocusAreas && (typeof manifest.threat_model_digest !== "string" || !/^[a-f0-9]{64}$/.test(manifest.threat_model_digest))) {
    throw new Error("Focus Area manifest lacks a valid threat_model_digest");
  }
  manifest.manifest_digest = manifestDigest(manifest);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: outputPath, kind: isThreatModel ? "threat-model" : "focus-areas", audit_id: manifest.audit_id, manifest_digest: manifest.manifest_digest })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
