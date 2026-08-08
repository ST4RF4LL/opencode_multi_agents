#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { objectDigest } from "./coverage-v2-common.mjs";
import { verifyLedger } from "./coverage-ledger-core.mjs";
import { buildCoverageSummary, renderCoverageMarkdown } from "./render-coverage-summary.mjs";

function parseArgs(argv) {
  const args = { mode: "complete" };
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["summary", "markdown", "plan", "ledger", "structural"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  if (!["complete", "policy", "partial"].includes(args.mode)) throw new Error("--mode must be complete, policy, or partial");
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [claimed, claimedMarkdown, structural] = await Promise.all([
    readFile(resolve(args.summary), "utf8").then(JSON.parse),
    readFile(resolve(args.markdown), "utf8"),
    readFile(resolve(args.structural), "utf8").then(JSON.parse),
  ]);
  if (claimed.schema_version !== 3 || claimed.manifest_digest !== objectDigest(claimed)) {
    throw new Error("Coverage v3 summary manifest digest mismatch");
  }
  if (structural.manifest_digest !== objectDigest(structural)) {
    throw new Error("Structural verification manifest digest mismatch");
  }
  const ledger = await verifyLedger({
    planPath: resolve(args.plan),
    ledgerPath: resolve(args.ledger),
    requireFinalized: args.mode === "complete",
    requirePolicyFinalized: args.mode === "policy",
  });
  if (args.mode === "partial" && ledger.seal_state === "OPEN") {
    throw new Error("Partial summary is not bound to a sealed checkpoint or terminal partial ledger");
  }
  const expected = buildCoverageSummary({
    plan: ledger.plan,
    ledgerState: ledger.state,
    structural,
    ledgerComplete: ledger.complete,
    ledgerPolicySatisfied: ledger.policy_satisfied,
    policyMode: ledger.policy_mode,
    sealState: ledger.seal_state,
  });
  if (!isDeepStrictEqual(claimed, expected)) throw new Error("Claimed coverage percentages or counts do not equal machine-derived values");
  if (claimedMarkdown !== renderCoverageMarkdown(expected)) throw new Error("Coverage Markdown is not the machine-derived rendering of the summary");
  process.stdout.write(`${JSON.stringify({
    valid: true,
    complete: claimed.complete,
    coverage_status: claimed.coverage_status,
    seal_state: claimed.seal_state,
    manifest_digest: claimed.manifest_digest,
  })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
