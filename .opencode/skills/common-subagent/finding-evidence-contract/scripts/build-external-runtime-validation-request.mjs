#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { buildExternalRuntimeValidationRequest } from "./external-runtime-validation-contract.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const field of ["request-id", "finding", "adjudication", "policy", "repository", "session-id", "output"]) {
    if (!args[field]) throw new Error(`Required argument missing: --${field}`);
  }
  return args;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function readJsonBytes(path) {
  const resolved = resolve(path);
  const bytes = await readFile(resolved);
  return { path: resolved, bytes, value: JSON.parse(bytes.toString("utf8")) };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [findingFile, adjudicationFile, policyFile, repositoryFile, proofGapsFile] = await Promise.all([
    readJsonBytes(args.finding),
    readJsonBytes(args.adjudication),
    readJsonBytes(args.policy),
    readJsonBytes(args.repository),
    args["proof-gaps"] ? readJsonBytes(args["proof-gaps"]) : null,
  ]);
  const decisionIndex = (adjudicationFile.value.decisions ?? [])
    .findIndex(decision => decision.finding_id === findingFile.value.finding_id);
  if (decisionIndex < 0) throw new Error("Adjudication manifest has no decision for the supplied finding");
  const request = buildExternalRuntimeValidationRequest({
    requestId: args["request-id"],
    finding: findingFile.value,
    findingArtifact: { path: findingFile.path, sha256: sha256(findingFile.bytes) },
    decision: adjudicationFile.value.decisions[decisionIndex],
    adjudication: {
      path: adjudicationFile.path,
      sha256: sha256(adjudicationFile.bytes),
      json_pointer: `/decisions/${decisionIndex}`,
    },
    repository: repositoryFile.value,
    policy: policyFile.value,
    proofGaps: proofGapsFile?.value,
    exportedBySessionId: args["session-id"],
  });
  const output = resolve(args.output);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(request, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({
    output,
    request_id: request.request_id,
    finding_id: request.finding_id,
    packet_digest: request.packet_digest,
  })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
