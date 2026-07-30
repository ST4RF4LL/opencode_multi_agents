#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { validateCvssAssessmentManifest } from "./cvss-assessment-contract.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["adjudication", "assessment"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [adjudication, assessment] = await Promise.all([
    readFile(resolve(args.adjudication), "utf8").then(JSON.parse),
    readFile(resolve(args.assessment), "utf8").then(JSON.parse),
  ]);
  const errors = validateCvssAssessmentManifest(assessment, adjudication);
  if (errors.length > 0) throw new Error(`CVSS assessment is invalid:\n- ${errors.join("\n- ")}`);
  process.stdout.write(`${JSON.stringify({ complete: true, audit_id: assessment.audit_id, assessments: assessment.assessments.length })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
