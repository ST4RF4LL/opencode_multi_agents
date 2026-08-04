#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  validateStageContractRegistry,
  validateStageEnvelope,
} from "./stage-agent-contract.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_REGISTRY = resolve(HERE, "../contracts/stage-agent-contracts.json");
const DEFAULT_ROLES = resolve(HERE, "../../../../agent-manifest/roles.json");

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  if (!args.envelope) throw new Error("Required argument missing: --envelope");
  return args;
}

async function readJson(path) {
  return JSON.parse(await readFile(resolve(path), "utf8"));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [registry, roles, envelope, inputEnvelope] = await Promise.all([
    readJson(args.registry ?? DEFAULT_REGISTRY),
    readJson(args.roles ?? DEFAULT_ROLES),
    readJson(args.envelope),
    args.input ? readJson(args.input) : null,
  ]);
  const registryErrors = validateStageContractRegistry(registry, roles);
  if (registryErrors.length > 0) throw new Error(`Stage contract registry is invalid:\n- ${registryErrors.join("\n- ")}`);
  if (envelope.direction === "OUTPUT" && !inputEnvelope) {
    throw new Error("An OUTPUT envelope requires --input with its sealed INPUT envelope");
  }
  const errors = validateStageEnvelope(envelope, registry, { roles, inputEnvelope });
  if (errors.length > 0) throw new Error(`Stage/Agent envelope is invalid:\n- ${errors.join("\n- ")}`);
  process.stdout.write(`${JSON.stringify({
    valid: true,
    contract_id: envelope.contract_id,
    direction: envelope.direction,
    status: envelope.status ?? null,
    envelope_digest: envelope.envelope_digest,
  })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
