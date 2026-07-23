#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { buildCoverageSummary } from "./render-coverage-summary.mjs";
import { verifyLedger } from "./coverage-ledger-core.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["audit-id", "plan", "ledger", "structural", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const structuralPath = resolve(args.structural);
  const structural = JSON.parse(await readFile(structuralPath, "utf8"));
  const ledger = await verifyLedger({
    planPath: resolve(args.plan),
    ledgerPath: resolve(args.ledger),
    requireFinalized: true,
  });
  const issues = [...ledger.issues];
  if (ledger.plan.audit_id !== args["audit-id"]) issues.push({ code: "AUDIT_ID_MISMATCH" });
  if (structural.audit_id !== args["audit-id"] || structural.scope_digest !== ledger.plan.scope_digest) {
    issues.push({ code: "STRUCTURAL_VERIFICATION_BINDING_MISMATCH" });
  }
  if (structural.complete !== true) issues.push({ code: "STRUCTURAL_VERIFICATION_INCOMPLETE" });
  const summary = buildCoverageSummary({
    plan: ledger.plan,
    ledgerState: ledger.state,
    structural,
    ledgerComplete: ledger.complete,
  });
  const complete = issues.length === 0 && summary.complete;
  const verification = {
    schema_version: 2,
    audit_id: args["audit-id"],
    scope_digest: ledger.plan.scope_digest,
    catalog_profile: ledger.plan.catalog_profile_id,
    required_lenses: ["sink-driven", "control-driven", "config-driven"],
    active_domains: ledger.plan.universes.active_domains,
    inputs: {
      coverage_plan: resolve(args.plan),
      coverage_plan_digest: ledger.plan.manifest_digest,
      coverage_ledger: resolve(args.ledger),
      ledger_chain_head: ledger.events.at(-1)?.event_hash ?? null,
      structural_verification: structuralPath,
    },
    expected: {
      ...ledger.plan.universes,
      atomic_checks: ledger.plan.summary.atomic_checks,
      required_checks: ledger.plan.summary.required,
      not_applicable_checks: ledger.plan.summary.not_applicable,
      unknown_checks: ledger.plan.summary.unknown,
    },
    observed: {
      ledger_events: ledger.events.length,
      verified_checks: [...ledger.state.values()].filter(item => item.execution_state === "VERIFIED").length,
      finding_checks: [...ledger.state.values()].filter(item => item.result_state === "FINDING").length,
      finalized: Boolean(ledger.finalization),
    },
    gaps: ledger.gaps.map(item => ({
      check_id: item.check.check_id,
      subject_kind: item.check.subject_kind,
      subject_id: item.check.subject_id,
      vulnerability_type_id: item.check.vulnerability_type_id,
      domain: item.check.domain,
      lens: item.check.lens,
      execution_state: item.execution_state,
      result_state: item.result_state,
    })),
    invalid: [],
    issues,
    summary,
    complete,
    claim_boundary: "Coverage v2 proves that the frozen file/function universe passed structural accounting and every REQUIRED sparse vulnerability-type/interface check has a valid hash-chained VERIFIED decision. It does not prove absence of vulnerabilities.",
  };
  const output = resolve(args.output);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(verification, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({
    output,
    complete,
    expected: verification.expected,
    observed: verification.observed,
    gaps: verification.gaps.length,
    issues: issues.length,
  })}\n`);
  if (!complete) process.exitCode = 2;
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
