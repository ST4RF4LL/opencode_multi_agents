#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { candidateManifestDigest, validateCandidateManifest } from "./finding-adjudication-contract.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["input", "session-id", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const input = JSON.parse(await readFile(resolve(args.input), "utf8"));
  const inputErrors = validateCandidateManifest(input);
  if (inputErrors.length > 0) throw new Error(`Candidate manifest is invalid:\n- ${inputErrors.join("\n- ")}`);
  if (input.candidates.length !== 0) throw new Error("Empty adjudication is allowed only for a verified zero-candidate input");
  const output = {
    schema_version: 1,
    audit_id: input.audit_id,
    scope_digest: input.scope_digest,
    input_manifest_digest: input.manifest_digest,
    adjudicator_session_id: args["session-id"],
    decisions: [],
  };
  output.manifest_digest = candidateManifestDigest(output);
  const outputPath = resolve(args.output);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(output, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: outputPath, audit_id: output.audit_id, decisions: 0 })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
