#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseFindingArtifact } from "./finding-contract.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  if (!args.input) throw new Error("--input is required");
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const path = resolve(args.input);
  const { finding, finding_object_digest: digest } = parseFindingArtifact(await readFile(path), {
    expectedFindingId: args["finding-id"],
    auditId: args["audit-id"],
    scopeDigest: args["scope-digest"],
  });
  process.stdout.write(`${JSON.stringify({ input: path, finding_id: finding.finding_id, finding_object_digest: digest, valid: true })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
