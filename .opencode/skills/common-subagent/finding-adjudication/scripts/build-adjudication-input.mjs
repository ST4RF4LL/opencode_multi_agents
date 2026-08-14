#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { objectDigest } from "../../audit-coverage-accounting/scripts/coverage-v2-common.mjs";
import { verifyLedger } from "../../audit-coverage-accounting/scripts/coverage-ledger-core.mjs";
import { parseFindingArtifact } from "../../finding-evidence-contract/scripts/finding-contract.mjs";
import { ADJUDICATION_SCHEMA_VERSION, candidateManifestDigest, validateCandidateManifest } from "./finding-adjudication-contract.mjs";
import { readAuditTodo } from "../../../../scripts/audit-todo-core.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["audit-id", "plan", "structural", "output"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  }
  if (!args.ledger && !(args.todo && args["reports-root"])) {
    throw new Error("Required argument missing: use legacy --ledger or local --todo together with --reports-root");
  }
  return args;
}

function acceptedCoverageFindings(structural) {
  const findings = structural.finding_intake?.accepted_findings;
  if (!Array.isArray(findings)) throw new Error("Structural verification has no accepted finding intake");
  return new Map(findings
    .filter(finding => finding.discovery_track === "coverage")
    .map(finding => [finding.finding_id, finding]));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const structuralPath = resolve(args.structural);
  const structural = JSON.parse(await readFile(structuralPath, "utf8"));
  if (structural.manifest_digest !== objectDigest(structural)) throw new Error("Structural verification digest mismatch");
  const plan = JSON.parse(await readFile(resolve(args.plan), "utf8"));
  if (plan.audit_id !== args["audit-id"] || structural.audit_id !== args["audit-id"]
    || structural.scope_digest !== plan.scope_digest) {
    throw new Error("Audit/scope binding mismatch across Plan and structural verification");
  }
  const accepted = acceptedCoverageFindings(structural);
  const candidates = [];
  if (args.todo) {
    const reportsRoot = resolve(args["reports-root"]);
    const todo = await readAuditTodo(resolve(args.todo));
    if (todo.audit_id !== args["audit-id"]) throw new Error("Local audit todo belongs to another audit_id");
    const doneReports = new Set(todo.items
      .filter(item => item.status === "DONE" && typeof item.artifact_path === "string")
      .map(item => resolve(reportsRoot, item.artifact_path)));
    for (const acceptedFinding of accepted.values()) {
      const check = plan.checks.find(item => item.check_id === acceptedFinding.primary_check_id);
      if (!check) throw new Error(`Structural finding references an unknown check: ${acceptedFinding.primary_check_id}`);
      const reportPath = resolve(acceptedFinding.report_path);
      if (!doneReports.has(reportPath)) throw new Error(`Accepted finding is not backed by a DONE local packet report: ${acceptedFinding.finding_id}`);
      const report = JSON.parse(await readFile(reportPath, "utf8"));
      const rawFinding = Array.isArray(report.findings) ? report.findings.find(item => item?.finding_id === acceptedFinding.finding_id) : null;
      if (!rawFinding) throw new Error(`Accepted finding is absent from its packet report: ${acceptedFinding.finding_id}`);
      const { finding, finding_object_digest: findingObjectDigest } = parseFindingArtifact(JSON.stringify(rawFinding), {
        expectedFindingId: acceptedFinding.finding_id,
        auditId: plan.audit_id,
        scopeDigest: plan.scope_digest,
        check,
      });
      if (findingObjectDigest !== acceptedFinding.finding_object_digest) {
        throw new Error(`Finding object digest mismatch for ${acceptedFinding.finding_id}`);
      }
      candidates.push({
        finding_id: finding.finding_id,
        finding_object_digest: findingObjectDigest,
        primary_check_id: check.check_id,
        artifact: { path: reportPath, sha256: null, bytes: null },
        source_reports: [acceptedFinding.report_path],
        finding,
      });
    }
  } else {
    const ledger = await verifyLedger({
      planPath: resolve(args.plan),
      ledgerPath: resolve(args.ledger),
      requireFinalized: false,
    });
    if (ledger.plan.audit_id !== plan.audit_id || ledger.plan.scope_digest !== plan.scope_digest) {
      throw new Error("Legacy Ledger does not match the frozen Plan");
    }
    for (const event of ledger.events.filter(item => item.event_type === "DECISION" && item.result_state === "FINDING")) {
      const check = plan.checks.find(item => item.check_id === event.check_id);
      if (!check) throw new Error(`Ledger decision references an unknown check: ${event.check_id}`);
      for (const artifact of event.finding_artifacts ?? []) {
        const acceptedFinding = accepted.get(artifact.finding_id);
        if (!acceptedFinding) throw new Error(`Ledger finding is not an accepted structural coverage finding: ${artifact.finding_id}`);
        if (acceptedFinding.primary_check_id !== event.check_id) throw new Error(`Structural primary check mismatch for finding ${artifact.finding_id}`);
        const bytes = await readFile(artifact.path);
        const { finding, finding_object_digest: findingObjectDigest } = parseFindingArtifact(bytes, {
          expectedFindingId: artifact.finding_id,
          auditId: plan.audit_id,
          scopeDigest: plan.scope_digest,
          check,
        });
        if (findingObjectDigest !== artifact.finding_object_digest || findingObjectDigest !== acceptedFinding.finding_object_digest) {
          throw new Error(`Finding object digest mismatch for ${artifact.finding_id}`);
        }
        candidates.push({ finding_id: finding.finding_id, finding_object_digest: findingObjectDigest, primary_check_id: check.check_id, artifact: { path: artifact.path, sha256: artifact.sha256, bytes: artifact.bytes }, source_reports: [acceptedFinding.report_path], finding });
      }
    }
  }
  const manifest = {
    schema_version: ADJUDICATION_SCHEMA_VERSION,
    audit_id: plan.audit_id,
    scope_digest: plan.scope_digest,
    plan_digest: plan.manifest_digest,
    structural_digest: structural.manifest_digest,
    candidates: candidates.sort((left, right) => left.finding_id.localeCompare(right.finding_id)),
  };
  manifest.manifest_digest = candidateManifestDigest(manifest);
  const errors = validateCandidateManifest(manifest);
  if (errors.length > 0) throw new Error(`Adjudication input is invalid:\n- ${errors.join("\n- ")}`);
  const outputPath = resolve(args.output);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: outputPath, audit_id: manifest.audit_id, candidates: manifest.candidates.length })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
