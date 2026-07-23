#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { objectDigest } from "./coverage-v2-common.mjs";
import { verifyLedger } from "./coverage-ledger-core.mjs";
import { buildCoverageSummary } from "./render-coverage-summary.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["summary", "plan", "ledger", "structural"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [claimed, structural] = await Promise.all([
    readFile(resolve(args.summary), "utf8").then(JSON.parse),
    readFile(resolve(args.structural), "utf8").then(JSON.parse),
  ]);
  if (claimed.manifest_digest !== objectDigest(claimed)) throw new Error("Coverage summary manifest digest mismatch");
  const ledger = await verifyLedger({ planPath: resolve(args.plan), ledgerPath: resolve(args.ledger), requireFinalized: true });
  const expected = buildCoverageSummary({
    plan: ledger.plan,
    ledgerState: ledger.state,
    structural,
    ledgerComplete: ledger.complete,
  });
  if (!isDeepStrictEqual(claimed, expected)) throw new Error("Claimed coverage percentages or counts do not equal machine-derived values");
  process.stdout.write(`${JSON.stringify({ valid: true, complete: claimed.complete, manifest_digest: claimed.manifest_digest })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
