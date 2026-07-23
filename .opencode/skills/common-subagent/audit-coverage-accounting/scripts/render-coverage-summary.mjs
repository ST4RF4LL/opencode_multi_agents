#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { objectDigest } from "./coverage-v2-common.mjs";
import { verifyLedger } from "./coverage-ledger-core.mjs";

function ratio(numerator, denominator) {
  if (denominator === 0) return { state: "NOT_APPLICABLE", numerator: 0, denominator: 0, percentage: null };
  return {
    state: numerator === denominator ? "COMPLETE" : "INCOMPLETE",
    numerator,
    denominator,
    percentage: Number(((numerator / denominator) * 100).toFixed(2)),
  };
}

function unionKeys(...arrays) {
  return new Set(arrays.flatMap(array => array.map(item => JSON.stringify(item))));
}

function structuralMetric(kind, structural) {
  const plural = kind === "file" ? "files" : "functions";
  const expectedEntities = structural.expected?.[plural] ?? 0;
  const domains = structural.expected?.file_function_coverage_domains?.length ?? 0;
  const lenses = structural.expected?.lenses_per_item ?? 0;
  const required = expectedEntities * domains * lenses;
  const failures = unionKeys(structural.missing?.[plural] ?? [], structural.invalid?.[plural] ?? []).size;
  const verified = Math.max(0, required - failures);
  const entityFailures = kind === "file"
    ? new Set([
      ...(structural.missing?.files ?? []).map(item => item.path),
      ...(structural.invalid?.files ?? []).map(item => item.path),
      ...(structural.missing?.functions ?? []).map(item => item.path),
      ...(structural.invalid?.functions ?? []).map(item => item.path),
    ])
    : new Set([
      ...(structural.missing?.functions ?? []).map(item => item.function_id),
      ...(structural.invalid?.functions ?? []).map(item => item.function_id),
    ]);
  return {
    checks: ratio(verified, required),
    complete_entities: ratio(Math.max(0, expectedEntities - entityFailures.size), expectedEntities),
    gaps: failures,
    ...(kind === "file" ? {
      contained_function_gap_files: new Set([
        ...(structural.missing?.functions ?? []).map(item => item.path),
        ...(structural.invalid?.functions ?? []).map(item => item.path),
      ]).size,
    } : {}),
  };
}

function stateForCheck(ledgerState, checkId) {
  return ledgerState.get(checkId)?.execution_state ?? null;
}

function groupedCompleteness(requiredChecks, ledgerState, keyFor) {
  const groups = new Map();
  for (const check of requiredChecks) {
    const key = keyFor(check);
    const group = groups.get(key) ?? [];
    group.push(check);
    groups.set(key, group);
  }
  const complete = [...groups.values()].filter(checks => checks.every(check => stateForCheck(ledgerState, check.check_id) === "VERIFIED")).length;
  return ratio(complete, groups.size);
}

function lensMetrics(plan, ledgerState, lens) {
  const required = plan.checks.filter(check => check.applicability === "REQUIRED" && check.lens === lens);
  const verified = required.filter(check => stateForCheck(ledgerState, check.check_id) === "VERIFIED").length;
  const typeChecks = required.filter(check => check.subject_kind === "catalog-domain");
  const interfaceChecks = required.filter(check => check.subject_kind === "interface");
  return {
    all_checks: ratio(verified, required.length),
    vulnerability_type_checks: ratio(
      typeChecks.filter(check => stateForCheck(ledgerState, check.check_id) === "VERIFIED").length,
      typeChecks.length,
    ),
    fully_checked_vulnerability_types: groupedCompleteness(required, ledgerState, check => `${check.domain}|${check.vulnerability_type_id}`),
    interface_checks: ratio(
      interfaceChecks.filter(check => stateForCheck(ledgerState, check.check_id) === "VERIFIED").length,
      interfaceChecks.length,
    ),
    fully_checked_interfaces: groupedCompleteness(interfaceChecks, ledgerState, check => check.subject_id),
  };
}

export function buildCoverageSummary({ plan, ledgerState, structural, ledgerComplete }) {
  const required = plan.checks.filter(check => check.applicability === "REQUIRED");
  const verified = required.filter(check => stateForCheck(ledgerState, check.check_id) === "VERIFIED").length;
  const unknown = plan.checks.filter(check => check.applicability === "UNKNOWN").length;
  const notApplicable = plan.checks.filter(check => check.applicability === "NOT_APPLICABLE").length;
  const interfaceRequired = required.filter(check => check.subject_kind === "interface");
  const directions = {};
  for (const direction of ["ingress", "egress", "bidirectional"]) {
    const checks = interfaceRequired.filter(check => check.interface_direction === direction);
    directions[direction] = {
      checks: ratio(checks.filter(check => stateForCheck(ledgerState, check.check_id) === "VERIFIED").length, checks.length),
      complete_interfaces: groupedCompleteness(checks, ledgerState, check => check.subject_id),
    };
  }
  const knownCoverage = ratio(verified, required.length);
  const conservativeLowerBound = ratio(verified, required.length + unknown);
  const summary = {
    schema_version: 2,
    audit_id: plan.audit_id,
    plan_digest: plan.manifest_digest,
    scope_digest: plan.scope_digest,
    accounting: {
      required: required.length,
      verified,
      unknown,
      not_applicable: notApplicable,
      known_coverage: knownCoverage,
      conservative_lower_bound: conservativeLowerBound,
    },
    vulnerability_types: {
      checks: ratio(verified, required.length),
      fully_checked: groupedCompleteness(required, ledgerState, check => `${check.domain}|${check.vulnerability_type_id}`),
      by_lens: Object.fromEntries(plan.required_lenses?.map(lens => [lens, lensMetrics(plan, ledgerState, lens)]) ?? [
        ["sink-driven", lensMetrics(plan, ledgerState, "sink-driven")],
        ["control-driven", lensMetrics(plan, ledgerState, "control-driven")],
        ["config-driven", lensMetrics(plan, ledgerState, "config-driven")],
      ]),
    },
    external_interfaces: {
      checks: ratio(
        interfaceRequired.filter(check => stateForCheck(ledgerState, check.check_id) === "VERIFIED").length,
        interfaceRequired.length,
      ),
      complete_interfaces: groupedCompleteness(interfaceRequired, ledgerState, check => check.subject_id),
      by_direction: directions,
    },
    files: structuralMetric("file", structural),
    functions: structuralMetric("function", structural),
    complete: ledgerComplete && structural.complete === true && unknown === 0 && verified === required.length,
    claim_boundary: "All ratios are calculated from frozen machine inventories and verified ledger states. They measure completion of planned checks, not absence of vulnerabilities.",
  };
  summary.manifest_digest = objectDigest(summary);
  return summary;
}

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["plan", "ledger", "structural", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const structural = JSON.parse(await readFile(resolve(args.structural), "utf8"));
  const ledger = await verifyLedger({ planPath: resolve(args.plan), ledgerPath: resolve(args.ledger), requireFinalized: true });
  const summary = buildCoverageSummary({ plan: ledger.plan, ledgerState: ledger.state, structural, ledgerComplete: ledger.complete });
  const output = resolve(args.output);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output, complete: summary.complete, accounting: summary.accounting, manifest_digest: summary.manifest_digest })}\n`);
  if (!summary.complete) process.exitCode = 2;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
}
