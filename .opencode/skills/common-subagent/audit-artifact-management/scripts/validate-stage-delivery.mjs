#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  validateStageDeliveryManifest,
  validateStageDeliveryRegistry,
} from "./stage-delivery-contract.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_REGISTRY = resolve(HERE, "../contracts/workbench-stage-deliveries.json");
const DEFAULT_STAGE_AGENT_REGISTRY = resolve(HERE, "../contracts/stage-agent-contracts.json");

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) throw new Error(`Invalid argument: ${token}`);
    const key = token.slice(2);
    if (["registry-only"].includes(key)) args[key] = true;
    else {
      const value = argv[index + 1];
      if (value == null) throw new Error(`Missing value for --${key}`);
      args[key] = value;
      index += 1;
    }
  }
  if (!args["registry-only"] && !args.manifest) throw new Error("Required argument missing: --manifest or --registry-only");
  return args;
}

async function json(path) {
  return JSON.parse(await readFile(resolve(path), "utf8"));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [registry, stageAgentRegistry] = await Promise.all([
    json(args.registry ?? DEFAULT_REGISTRY),
    json(args["stage-agent-registry"] ?? DEFAULT_STAGE_AGENT_REGISTRY),
  ]);
  const registryErrors = validateStageDeliveryRegistry(registry, stageAgentRegistry);
  if (registryErrors.length > 0) throw new Error(`Stage delivery registry is invalid:\n- ${registryErrors.join("\n- ")}`);
  if (args["registry-only"]) {
    process.stdout.write(`${JSON.stringify({ complete: true, registry_id: registry.registry_id, stages: registry.stages.length, enforcement: registry.lifecycle.enforcement })}\n`);
    return;
  }
  const manifest = await json(args.manifest);
  const errors = validateStageDeliveryManifest(manifest, registry, { stageAgentRegistry });
  if (errors.length > 0) throw new Error(`Stage delivery manifest is invalid:\n- ${errors.join("\n- ")}`);
  process.stdout.write(`${JSON.stringify({ complete: true, audit_id: manifest.audit_id, stage_id: manifest.stage_id, round: manifest.round, status: manifest.status, manifest_digest: manifest.manifest_digest })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
