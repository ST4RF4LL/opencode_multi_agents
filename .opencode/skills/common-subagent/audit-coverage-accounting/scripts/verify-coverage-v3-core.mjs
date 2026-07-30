#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { objectDigest, sha256 } from "./coverage-v2-common.mjs";
import { verifyLedger } from "./coverage-ledger-core.mjs";
import { buildCoverageSummary, renderCoverageMarkdown } from "./render-coverage-summary.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const args = { functions: [], mode: "complete" };
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    const key = token.slice(2);
    if (key === "functions") args.functions.push(value);
    else args[key] = value;
  }
  for (const key of [
    "root",
    "audit-id",
    "plan",
    "ledger",
    "scope",
    "interfaces",
    "interface-extractors",
    "snapshot-index",
    "reports-dir",
    "catalog",
    "structural-output",
    "summary-output",
    "markdown-output",
    "output",
  ]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  if (args.functions.length === 0) throw new Error("At least one --functions manifest is required");
  if (!["complete", "partial"].includes(args.mode)) throw new Error("--mode must be complete or partial");
  if (args.structural) throw new Error("Coverage v3 does not accept caller-supplied structural verification");
  return args;
}

function runStructural(args) {
  const childArgs = [
    resolve(HERE, "verify-coverage.mjs"),
    "--root", resolve(args.root),
    "--audit-id", args["audit-id"],
    "--scope", resolve(args.scope),
    "--interfaces", resolve(args.interfaces),
    "--interface-extractors", resolve(args["interface-extractors"]),
    "--snapshot-index", resolve(args["snapshot-index"]),
    ...args.functions.flatMap(path => ["--functions", resolve(path)]),
    "--reports-dir", resolve(args["reports-dir"]),
    "--catalog", resolve(args.catalog),
    "--output", resolve(args["structural-output"]),
  ];
  const result = spawnSync(process.execPath, childArgs, {
    encoding: "utf8",
    maxBuffer: 128 * 1024 * 1024,
  });
  if (![0, 2].includes(result.status)) {
    throw new Error(`Trusted structural verifier failed with ${result.status}\n${result.stderr}\n${result.stdout}`);
  }
  return result.status;
}

function universeIssues(plan, structural) {
  const issues = [];
  const expected = structural.expected ?? {};
  if (expected.files !== plan.universes.files) issues.push({ code: "STRUCTURAL_FILE_UNIVERSE_MISMATCH" });
  if (expected.functions !== plan.universes.functions) issues.push({ code: "STRUCTURAL_FUNCTION_UNIVERSE_MISMATCH" });
  if (expected.confirmed_external_interfaces !== plan.inventory.confirmed_interfaces) {
    issues.push({ code: "STRUCTURAL_CONFIRMED_INTERFACE_UNIVERSE_MISMATCH" });
  }
  if (expected.candidate_external_interfaces !== plan.inventory.candidate_interfaces) {
    issues.push({ code: "STRUCTURAL_CANDIDATE_INTERFACE_UNIVERSE_MISMATCH" });
  }
  if (structural.interface_extractor_verification?.complete !== plan.inventory.extractor_complete) {
    issues.push({ code: "STRUCTURAL_INTERFACE_EXTRACTOR_STATE_MISMATCH" });
  }
  return issues;
}

function findingReconciliation(ledger, structural) {
  const intake = structural.finding_intake;
  const issues = [];
  if (!intake || !Array.isArray(intake.accepted_findings) || !Array.isArray(intake.quarantined_findings)) {
    return {
      issues: [{ code: "STRUCTURAL_FINDING_INTAKE_MISSING" }],
      accepted_report_findings: 0,
      ledger_finding_artifacts: 0,
    };
  }
  const accepted = intake.accepted_findings
    .filter(finding => finding.discovery_track === "coverage");
  const ledgerFindings = ledger.events
    .filter(event => event.event_type === "DECISION" && event.result_state === "FINDING")
    .flatMap(event => (event.finding_artifacts ?? []).map(artifact => ({
      finding_id: artifact.finding_id,
      finding_object_digest: artifact.finding_object_digest,
      check_id: event.check_id,
      plan_digest: event.plan_digest,
      artifact_sha256: artifact.sha256,
    })));
  const acceptedById = new Map();
  for (const finding of accepted) {
    const existing = acceptedById.get(finding.finding_id) ?? [];
    existing.push(finding);
    acceptedById.set(finding.finding_id, existing);
  }
  const ledgerById = new Map();
  for (const finding of ledgerFindings) {
    const existing = ledgerById.get(finding.finding_id) ?? [];
    existing.push(finding);
    ledgerById.set(finding.finding_id, existing);
  }

  for (const [findingId, references] of acceptedById) {
    if (references.length > 1) {
      issues.push({ code: "DUPLICATE_ACCEPTED_REPORT_FINDING", finding_id: findingId, reports: references.map(item => item.report_path) });
      continue;
    }
    const [reference] = references;
    const attested = ledgerById.get(findingId) ?? [];
    if (attested.length === 0) {
      issues.push({ code: "UNATTESTED_REPORT_FINDING", finding_id: findingId, report: reference.report_path });
      continue;
    }
    if (!attested.some(item => item.check_id === reference.primary_check_id)) {
      issues.push({
        code: "FINDING_PRIMARY_CHECK_MISMATCH",
        finding_id: findingId,
        report_primary_check_id: reference.primary_check_id,
        ledger_check_ids: attested.map(item => item.check_id),
      });
    }
    if (!attested.some(item => item.finding_object_digest === reference.finding_object_digest)) {
      issues.push({
        code: "FINDING_ARTIFACT_DIGEST_MISMATCH",
        finding_id: findingId,
        report_finding_object_digest: reference.finding_object_digest,
        ledger_finding_object_digests: attested.map(item => item.finding_object_digest),
      });
    }
  }
  for (const [findingId, artifacts] of ledgerById) {
    const references = acceptedById.get(findingId) ?? [];
    if (!references.some(reference => artifacts.some(artifact => artifact.check_id === reference.primary_check_id
      && artifact.finding_object_digest === reference.finding_object_digest))) {
      issues.push({
        code: "ORPHAN_LEDGER_FINDING",
        finding_id: findingId,
        check_ids: artifacts.map(item => item.check_id),
      });
    }
  }
  return {
    issues,
    accepted_report_findings: accepted.length,
    ledger_finding_artifacts: ledgerFindings.length,
  };
}

export async function main() {
  const args = parseArgs(process.argv.slice(2));
  const outputPaths = [
    args["structural-output"],
    args["summary-output"],
    args["markdown-output"],
    args.output,
  ].map(path => resolve(path));
  const inputPaths = [
    args.plan,
    args.ledger,
    args.scope,
    args.interfaces,
    args["interface-extractors"],
    args["snapshot-index"],
    args.catalog,
    ...args.functions,
  ].map(path => resolve(path));
  if (new Set(outputPaths).size !== outputPaths.length
    || outputPaths.some(path => inputPaths.includes(path))) {
    throw new Error("Coverage v3 outputs must be distinct and must not overwrite frozen inputs");
  }
  await Promise.all([
    mkdir(dirname(resolve(args["structural-output"])), { recursive: true }),
    mkdir(dirname(resolve(args["summary-output"])), { recursive: true }),
    mkdir(dirname(resolve(args["markdown-output"])), { recursive: true }),
    mkdir(dirname(resolve(args.output)), { recursive: true }),
  ]);
  const structuralStatus = runStructural(args);
  const [structural, snapshot] = await Promise.all([
    readFile(resolve(args["structural-output"]), "utf8").then(JSON.parse),
    readFile(resolve(args["snapshot-index"]), "utf8").then(JSON.parse),
  ]);
  if (structural.manifest_digest !== objectDigest(structural)) throw new Error("Trusted structural verification digest mismatch");
  if (snapshot.snapshot_digest !== objectDigest(snapshot, ["snapshot_digest"])) throw new Error("Snapshot index digest mismatch");

  const ledger = await verifyLedger({
    planPath: resolve(args.plan),
    ledgerPath: resolve(args.ledger),
    requireFinalized: args.mode === "complete",
  });
  if (args.mode === "partial" && ledger.seal_state === "OPEN") {
    throw new Error("Partial final gate requires a PARTIAL_CHECKPOINT");
  }
  const findings = findingReconciliation(ledger, structural);
  const issues = [...ledger.issues, ...universeIssues(ledger.plan, structural), ...findings.issues];
  if (ledger.plan.audit_id !== args["audit-id"]) issues.push({ code: "AUDIT_ID_MISMATCH" });
  if (ledger.plan.inputs.snapshot_digest !== snapshot.snapshot_digest) issues.push({ code: "PLAN_SNAPSHOT_BINDING_MISMATCH" });
  if (structural.audit_id !== args["audit-id"] || structural.scope_digest !== ledger.plan.scope_digest) {
    issues.push({ code: "STRUCTURAL_VERIFICATION_BINDING_MISMATCH" });
  }
  if (structuralStatus !== 0 || structural.complete !== true) issues.push({ code: "STRUCTURAL_VERIFICATION_INCOMPLETE" });
  const summary = buildCoverageSummary({
    plan: ledger.plan,
    ledgerState: ledger.state,
    structural,
    ledgerComplete: ledger.complete,
    sealState: ledger.seal_state,
  });
  const markdown = renderCoverageMarkdown(summary);
  const complete = args.mode === "complete" && issues.length === 0 && summary.complete;
  const verification = {
    schema_version: 3,
    coverage_model_version: ledger.plan.coverage_model_version,
    audit_id: args["audit-id"],
    scope_digest: ledger.plan.scope_digest,
    snapshot_digest: snapshot.snapshot_digest,
    catalog_profile: ledger.plan.catalog_profile_id,
    required_lenses: ledger.plan.required_lenses,
    active_domains: ledger.plan.universes.active_domains,
    seal_state: ledger.seal_state,
    coverage_status: summary.coverage_status,
    inputs: {
      coverage_plan: resolve(args.plan),
      coverage_plan_digest: ledger.plan.manifest_digest,
      coverage_ledger: resolve(args.ledger),
      ledger_chain_head: ledger.events.at(-1)?.event_hash ?? null,
      snapshot_index: resolve(args["snapshot-index"]),
      structural_verification: resolve(args["structural-output"]),
      structural_digest: structural.manifest_digest,
      coverage_summary: resolve(args["summary-output"]),
      coverage_summary_digest: summary.manifest_digest,
      coverage_markdown: resolve(args["markdown-output"]),
      coverage_markdown_sha256: sha256(markdown),
    },
    expected: {
      ...ledger.plan.universes,
      atomic_checks: ledger.plan.summary.atomic_checks,
      required_checks: ledger.plan.summary.required,
      not_applicable_checks: ledger.plan.summary.not_applicable,
      unknown_checks: ledger.plan.summary.unknown,
      inventory: ledger.plan.inventory,
    },
    observed: {
      ledger_events: ledger.events.length,
      verified_checks: [...ledger.state.values()].filter(item => item.execution_state === "VERIFIED").length,
      finding_checks: [...ledger.state.values()].filter(item => item.result_state === "FINDING").length,
      finalized: Boolean(ledger.finalization),
      checkpointed: Boolean(ledger.checkpoint),
    },
    finding_reconciliation: findings,
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
    claim_boundary: "Coverage v3 proves trusted structural accounting and receipt-backed execution only for a frozen, bounded plan. Partial checkpoints remain explicitly incomplete. It does not prove absence of vulnerabilities.",
  };
  verification.manifest_digest = objectDigest(verification);
  await Promise.all([
    writeFile(resolve(args["summary-output"]), `${JSON.stringify(summary, null, 2)}\n`, "utf8"),
    writeFile(resolve(args["markdown-output"]), markdown, "utf8"),
    writeFile(resolve(args.output), `${JSON.stringify(verification, null, 2)}\n`, "utf8"),
  ]);
  process.stdout.write(`${JSON.stringify({
    output: resolve(args.output),
    complete,
    coverage_status: verification.coverage_status,
    seal_state: verification.seal_state,
    expected: verification.expected,
    observed: verification.observed,
    gaps: verification.gaps.length,
    issues: issues.length,
  })}\n`);
  if (!complete) process.exitCode = 2;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
}
