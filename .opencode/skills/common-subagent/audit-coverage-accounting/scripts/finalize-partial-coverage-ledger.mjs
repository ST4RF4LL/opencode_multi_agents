#!/usr/bin/env node

import { finalizePartialLedger, verifyLedger } from "./coverage-ledger-core.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["plan", "ledger", "idempotency-key", "termination-reason"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = await finalizePartialLedger({
    planPath: args.plan,
    ledgerPath: args.ledger,
    idempotencyKey: args["idempotency-key"],
    terminationReason: args["termination-reason"],
  });
  const verification = await verifyLedger({ planPath: args.plan, ledgerPath: args.ledger, requireFinalized: false });
  process.stdout.write(`${JSON.stringify({
    finalized: true,
    audit_id: verification.plan.audit_id,
    sequence: result.finalization.sequence,
    idempotent_replay: result.idempotent_replay,
    seal_state: verification.seal_state,
    complete: false,
    gaps: verification.gaps.length,
  })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
