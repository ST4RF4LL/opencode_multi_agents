#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { buildCvssAssessmentManifest } from "./cvss-assessment-contract.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["claims", "adjudication", "routing", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [claims, adjudication, routing] = await Promise.all([
    readFile(resolve(args.claims), "utf8").then(JSON.parse),
    readFile(resolve(args.adjudication), "utf8").then(JSON.parse),
    readFile(resolve(args.routing), "utf8").then(JSON.parse),
  ]);
  const manifest = buildCvssAssessmentManifest(claims, adjudication, routing);
  const output = resolve(args.output);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output, audit_id: manifest.audit_id, assessments: manifest.assessments.length })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
