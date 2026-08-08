#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { objectDigest } from "./coverage-v2-common.mjs";
import { verifyLedger } from "./coverage-ledger-core.mjs";

function ratio(numerator, denominator, zeroState = "NOT_APPLICABLE") {
  if (denominator === 0) return { state: zeroState, numerator: 0, denominator: 0, percentage: null };
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

function structuralMetric(kind, structural, zeroState) {
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
    checks: ratio(verified, required, zeroState),
    complete_entities: ratio(Math.max(0, expectedEntities - entityFailures.size), expectedEntities, zeroState),
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

function groupedCompleteness(requiredChecks, ledgerState, keyFor, zeroState = "NOT_APPLICABLE") {
  const groups = new Map();
  for (const check of requiredChecks) {
    const key = keyFor(check);
    const group = groups.get(key) ?? [];
    group.push(check);
    groups.set(key, group);
  }
  const complete = [...groups.values()].filter(checks => checks.every(check => stateForCheck(ledgerState, check.check_id) === "VERIFIED")).length;
  return ratio(complete, groups.size, zeroState);
}

function checkMetric(checks, ledgerState, zeroState = "NOT_APPLICABLE") {
  return ratio(checks.filter(check => stateForCheck(ledgerState, check.check_id) === "VERIFIED").length, checks.length, zeroState);
}

function interfaceIdsForCheck(check) {
  return Array.isArray(check.required_interface_ids) && check.required_interface_ids.length > 0
    ? check.required_interface_ids
    : [check.subject_id];
}

function interfaceMembershipMetric(checks, ledgerState, memberPredicate = () => true, zeroState = "NOT_APPLICABLE") {
  let required = 0;
  let verified = 0;
  for (const check of checks) {
    for (const interfaceId of interfaceIdsForCheck(check)) {
      if (!memberPredicate(interfaceId, check)) continue;
      required += 1;
      if (stateForCheck(ledgerState, check.check_id) === "VERIFIED") verified += 1;
    }
  }
  return ratio(verified, required, zeroState);
}

function completeInterfaces(checks, ledgerState, memberPredicate = () => true, zeroState = "NOT_APPLICABLE") {
  const groups = new Map();
  for (const check of checks) {
    for (const interfaceId of interfaceIdsForCheck(check)) {
      if (!memberPredicate(interfaceId, check)) continue;
      const group = groups.get(interfaceId) ?? [];
      group.push(check);
      groups.set(interfaceId, group);
    }
  }
  const complete = [...groups.values()].filter(group => group.every(check => stateForCheck(ledgerState, check.check_id) === "VERIFIED")).length;
  return ratio(complete, groups.size, zeroState);
}

function lensMetrics(plan, ledgerState, lens) {
  const required = plan.checks.filter(check => check.applicability === "REQUIRED" && check.lens === lens);
  const catalogChecks = required.filter(check => check.subject_kind === "catalog-domain");
  const interfaceChecks = required.filter(check => check.subject_kind === "interface");
  return {
    all_checks: checkMetric(required, ledgerState),
    vulnerability_type_checks: checkMetric(catalogChecks, ledgerState),
    fully_checked_vulnerability_types: groupedCompleteness(catalogChecks, ledgerState, check => `${check.domain}|${check.vulnerability_type_id}`),
    interface_checks: interfaceMembershipMetric(interfaceChecks, ledgerState),
    interface_work_packets: checkMetric(interfaceChecks, ledgerState),
    fully_checked_interfaces: completeInterfaces(interfaceChecks, ledgerState),
  };
}

function interfaceState(plan, knownMetric) {
  if (!plan.inventory.bounded) return "BLOCKED";
  return knownMetric.state;
}

function conservativeMetric({ verified, required, unknown, bounded, reason }) {
  if (bounded) return ratio(verified, required + unknown);
  return {
    state: "UNBOUNDED",
    numerator: verified,
    denominator: null,
    percentage: null,
    mathematical_floor_percentage: 0,
    reason,
  };
}

export function buildCoverageSummary({
  plan,
  ledgerState,
  structural,
  ledgerComplete,
  ledgerPolicySatisfied = false,
  policyMode = plan.coverage_policy?.mode ?? "assurance",
  sealState = "OPEN",
}) {
  const required = plan.checks.filter(check => check.applicability === "REQUIRED");
  const catalogRequired = required.filter(check => check.subject_kind === "catalog-domain");
  const interfaceRequired = required.filter(check => check.subject_kind === "interface");
  const verified = required.filter(check => stateForCheck(ledgerState, check.check_id) === "VERIFIED").length;
  const unknownChecks = plan.checks.filter(check => check.applicability === "UNKNOWN");
  const unknownCatalogChecks = unknownChecks.filter(check => check.subject_kind === "catalog-domain");
  const unknownInterfaceChecks = unknownChecks.filter(check => check.subject_kind === "interface");
  const notApplicableChecks = plan.checks.filter(check => check.applicability === "NOT_APPLICABLE");
  const knownCoverage = ratio(verified, required.length);
  const conservativeLowerBound = conservativeMetric({
    verified,
    required: required.length,
    unknown: unknownChecks.length,
    bounded: plan.inventory.bounded,
    reason: "Interface extraction gaps or unresolved candidates make the total atomic-check universe unbounded.",
  });
  const verifiedCatalog = catalogRequired.filter(check => stateForCheck(ledgerState, check.check_id) === "VERIFIED").length;
  const interfaceIndex = new Map((plan.interface_index ?? []).map(item => [item.interface_id, item]));
  const interfaceMemberships = interfaceRequired.reduce((sum, check) => sum + interfaceIdsForCheck(check).length, 0);
  const verifiedInterfaces = interfaceRequired.reduce((sum, check) => (
    sum + (stateForCheck(ledgerState, check.check_id) === "VERIFIED" ? interfaceIdsForCheck(check).length : 0)
  ), 0);
  const unknownInterfaceMemberships = unknownInterfaceChecks.reduce((sum, check) => sum + interfaceIdsForCheck(check).length, 0);
  const directions = {};
  for (const direction of ["ingress", "egress", "bidirectional"]) {
    const memberMatches = (interfaceId, check) => (interfaceIndex.get(interfaceId)?.direction ?? check.interface_direction) === direction;
    const knownChecks = interfaceMembershipMetric(interfaceRequired, ledgerState, memberMatches);
    directions[direction] = {
      state: interfaceState(plan, knownChecks),
      known_checks: knownChecks,
      complete_interfaces: completeInterfaces(interfaceRequired, ledgerState, memberMatches),
    };
  }
  const interfaceChecks = interfaceMembershipMetric(interfaceRequired, ledgerState);
  const summaryComplete = sealState === "FINALIZED_COMPLETE"
    && ledgerComplete && structural.complete === true && plan.complete
    && plan.inventory.bounded && unknownChecks.length === 0 && verified === required.length;
  const coverageStatus = summaryComplete
    ? "COMPLETE"
    : !plan.inventory.bounded || unknownChecks.length > 0
      ? "BLOCKED"
      : "PARTIAL";
  const unitChecks = (plan.coverage_units ?? []).map(unit => unit.check_ids.map(checkId => ledgerState.get(checkId)).filter(Boolean));
  const completeUnits = unitChecks.filter(checks => checks.length > 0
    && checks.every(item => item.execution_state === "VERIFIED")).length;
  const attestedChecks = required.filter(check => (ledgerState.get(check.check_id)?.receipt_ids?.length ?? 0) > 0).length;
  const policySatisfied = ledgerPolicySatisfied
    && (policyMode !== "assurance" || structural.complete === true);
  const summary = {
    schema_version: 3,
    coverage_model_version: plan.coverage_model_version,
    audit_id: plan.audit_id,
    plan_digest: plan.manifest_digest,
    scope_digest: plan.scope_digest,
    snapshot_digest: plan.inputs.snapshot_digest,
    structural_digest: objectDigest(structural, []),
    seal_state: sealState,
    policy_mode: policyMode,
    policy_satisfied: policySatisfied,
    workflow_status: policySatisfied ? "POLICY_SATISFIED" : sealState === "OPEN" ? "OPEN" : "INCOMPLETE",
    coverage_status: coverageStatus,
    execution: {
      assignment_units: ratio(completeUnits, unitChecks.length, "NOT_AVAILABLE"),
      required_units: unitChecks.length,
      complete_units: completeUnits,
    },
    evidence: {
      attested_checks: ratio(attestedChecks, required.length),
    },
    accounting: {
      required: required.length,
      verified,
      unknown: unknownChecks.length,
      not_applicable: notApplicableChecks.length,
      known_coverage: knownCoverage,
      conservative_lower_bound: conservativeLowerBound,
    },
    inventory: {
      state: plan.inventory.bounded ? "BOUNDED" : "UNBOUNDED",
      bounded: plan.inventory.bounded,
      files: ratio(plan.inventory.resolved_files, plan.inventory.eligible_files, "NOT_APPLICABLE"),
      eligible_files: plan.inventory.eligible_files,
      resolved_files: plan.inventory.resolved_files,
      gap_files: plan.inventory.gap_files,
      gap_file_ids: plan.inventory.gap_file_ids,
      confirmed_interfaces: plan.inventory.confirmed_interfaces,
      candidate_interfaces: plan.inventory.candidate_interfaces,
      candidate_interface_ids: plan.inventory.candidate_interface_ids,
      rejected_interfaces: plan.inventory.rejected_interfaces,
      unresolved_interfaces: plan.inventory.unresolved_interfaces,
      extractor_complete: plan.inventory.extractor_complete,
    },
    vulnerability_types: {
      checks: checkMetric(catalogRequired, ledgerState),
      conservative_lower_bound: conservativeMetric({
        verified: verifiedCatalog,
        required: catalogRequired.length,
        unknown: unknownCatalogChecks.length,
        bounded: true,
      }),
      fully_checked: groupedCompleteness(catalogRequired, ledgerState, check => `${check.domain}|${check.vulnerability_type_id}`),
      by_lens: Object.fromEntries((plan.required_lenses ?? []).map(lens => [lens, lensMetrics(plan, ledgerState, lens)])),
    },
    external_interfaces: {
      state: interfaceState(plan, interfaceChecks),
      known_checks: interfaceChecks,
      work_packets: checkMetric(interfaceRequired, ledgerState),
      conservative_lower_bound: conservativeMetric({
        verified: verifiedInterfaces,
        required: interfaceMemberships,
        unknown: unknownInterfaceMemberships,
        bounded: plan.inventory.bounded,
        reason: "Interface extraction gaps or unresolved candidates make the external-interface check universe unbounded.",
      }),
      complete_interfaces: completeInterfaces(interfaceRequired, ledgerState),
      confirmed_interfaces: plan.inventory.confirmed_interfaces,
      candidate_interfaces: plan.inventory.candidate_interfaces,
      by_direction: directions,
    },
    files: structuralMetric("file", structural, "NOT_APPLICABLE"),
    functions: structuralMetric(
      "function",
      structural,
      plan.universes.function_files > 0 ? "NOT_AVAILABLE" : "NOT_APPLICABLE",
    ),
    complete: summaryComplete,
    claim_boundary: "Ratios cover the frozen, enumerable v3 check universe. Inventory blockers are reported separately and suppress a numeric total lower bound. Completion measures review execution, not absence of vulnerabilities.",
  };
  summary.manifest_digest = objectDigest(summary);
  return summary;
}

function percent(metric) {
  return metric?.percentage == null ? metric?.state ?? "N/A" : `${metric.percentage.toFixed(2)}%`;
}

function fraction(metric) {
  return metric?.denominator == null ? "N/A" : `${metric.numerator}/${metric.denominator}`;
}

export function renderCoverageMarkdown(summary) {
  const rows = [
    ["All atomic checks", summary.accounting.known_coverage, summary.accounting.conservative_lower_bound, summary.coverage_status],
    ["Vulnerability types", summary.vulnerability_types.checks, summary.vulnerability_types.conservative_lower_bound, summary.vulnerability_types.checks.state],
    ["External interfaces", summary.external_interfaces.known_checks, summary.external_interfaces.conservative_lower_bound, summary.external_interfaces.state],
    ["Files", summary.files.checks, null, summary.files.checks.state],
    ["Functions", summary.functions.checks, null, summary.functions.checks.state],
  ];
  return [
    `<!-- GENERATED: coverage-v3 ${summary.manifest_digest} -->`,
    "## Machine-Derived Coverage v3",
    "",
    `Coverage status: **${summary.coverage_status}**. Policy: **${summary.policy_mode}** (${summary.policy_satisfied ? "SATISFIED" : "NOT SATISFIED"}). Ledger seal: **${summary.seal_state}**. Interface inventory: **${summary.inventory.state}**.`,
    "",
    "| Universe | Verified/Required | Known Coverage | Conservative Lower Bound | State |",
    "|---|---:|---:|---:|---|",
    ...rows.map(([name, metric, lower, state]) => `| ${name} | ${fraction(metric)} | ${percent(metric)} | ${lower ? percent(lower) : "N/A"} | ${state} |`),
    "",
    `Inventory files: ${summary.inventory.resolved_files}/${summary.inventory.eligible_files} resolved; ${summary.inventory.gap_files} gap files.`,
    `Interfaces: ${summary.inventory.confirmed_interfaces} confirmed, ${summary.inventory.candidate_interfaces} candidate, ${summary.inventory.rejected_interfaces} rejected.`,
    `Atomic checks: R=${summary.accounting.required}, V=${summary.accounting.verified}, U=${summary.accounting.unknown}, N=${summary.accounting.not_applicable}.`,
    "",
    summary.claim_boundary,
    "",
  ].join("\n");
}

function parseArgs(argv) {
  const args = { mode: "complete" };
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["plan", "ledger", "structural", "output", "markdown-output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  if (!["complete", "policy", "partial"].includes(args.mode)) throw new Error("--mode must be complete, policy, or partial");
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const output = resolve(args.output);
  const markdownOutput = resolve(args["markdown-output"]);
  const inputPaths = [args.plan, args.ledger, args.structural].map(path => resolve(path));
  if (output === markdownOutput || inputPaths.includes(output) || inputPaths.includes(markdownOutput)) {
    throw new Error("Coverage summary outputs must be distinct and must not overwrite inputs");
  }
  const structural = JSON.parse(await readFile(resolve(args.structural), "utf8"));
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
    throw new Error("Partial coverage output requires a sealed checkpoint or terminal partial ledger");
  }
  const summary = buildCoverageSummary({
    plan: ledger.plan,
    ledgerState: ledger.state,
    structural,
    ledgerComplete: ledger.complete,
    ledgerPolicySatisfied: ledger.policy_satisfied,
    policyMode: ledger.policy_mode,
    sealState: ledger.seal_state,
  });
  await Promise.all([
    mkdir(dirname(output), { recursive: true }),
    mkdir(dirname(markdownOutput), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(output, `${JSON.stringify(summary, null, 2)}\n`, "utf8"),
    writeFile(markdownOutput, renderCoverageMarkdown(summary), "utf8"),
  ]);
  process.stdout.write(`${JSON.stringify({
    output,
    markdown_output: markdownOutput,
    complete: summary.complete,
    coverage_status: summary.coverage_status,
    accounting: summary.accounting,
    manifest_digest: summary.manifest_digest,
  })}\n`);
  const accepted = args.mode === "complete" ? summary.complete
    : args.mode === "policy" ? summary.policy_satisfied : false;
  if (!accepted) process.exitCode = 2;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
}
