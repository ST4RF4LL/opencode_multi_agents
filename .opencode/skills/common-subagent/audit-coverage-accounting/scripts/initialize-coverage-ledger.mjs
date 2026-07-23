#!/usr/bin/env node

import { resolve } from "node:path";
import { initializeLedger } from "./coverage-ledger-core.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["plan", "ledger"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = await initializeLedger({ planPath: resolve(args.plan), ledgerPath: resolve(args.ledger) });
  process.stdout.write(`${JSON.stringify({
    initialized: result.initialized,
    audit_id: result.plan.audit_id,
    plan_digest: result.plan.manifest_digest,
    ledger: resolve(args.ledger),
    chain_head: result.genesis.event_hash,
  })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
