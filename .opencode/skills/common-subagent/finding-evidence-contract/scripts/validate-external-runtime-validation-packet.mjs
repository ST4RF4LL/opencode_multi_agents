#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  validateExternalRuntimeValidationRequest,
  validateExternalRuntimeValidationResult,
} from "./external-runtime-validation-contract.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  if (!args.request) throw new Error("Required argument missing: --request");
  return args;
}

async function readJson(path) {
  return JSON.parse(await readFile(resolve(path), "utf8"));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [request, result] = await Promise.all([
    readJson(args.request),
    args.result ? readJson(args.result) : null,
  ]);
  const errors = result
    ? validateExternalRuntimeValidationResult(result, request)
    : validateExternalRuntimeValidationRequest(request);
  if (errors.length > 0) throw new Error(`Runtime-validation packet is invalid:\n- ${errors.join("\n- ")}`);
  process.stdout.write(`${JSON.stringify({
    valid: true,
    request_id: request.request_id,
    request_digest: request.packet_digest,
    result_outcome: result?.outcome ?? null,
    result_digest: result?.packet_digest ?? null,
  })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
