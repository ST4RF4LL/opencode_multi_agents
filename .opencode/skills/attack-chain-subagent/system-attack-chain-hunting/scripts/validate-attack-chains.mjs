#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { validateAttackChainManifest } from "./attack-chain-contract.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["adjudication", "chains"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [adjudication, chains] = await Promise.all([
    readFile(resolve(args.adjudication), "utf8").then(JSON.parse),
    readFile(resolve(args.chains), "utf8").then(JSON.parse),
  ]);
  const errors = validateAttackChainManifest(chains, adjudication);
  if (errors.length > 0) throw new Error(`Attack-chain manifest is invalid:\n- ${errors.join("\n- ")}`);
  process.stdout.write(`${JSON.stringify({ complete: true, audit_id: chains.audit_id, chains: chains.chains.length })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
