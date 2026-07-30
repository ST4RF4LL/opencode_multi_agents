#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { objectDigest } from "../../audit-coverage-accounting/scripts/coverage-v2-common.mjs";
import { verifyLedger } from "../../audit-coverage-accounting/scripts/coverage-ledger-core.mjs";
import { parseFindingArtifact } from "../../finding-evidence-contract/scripts/finding-contract.mjs";
import { ADJUDICATION_SCHEMA_VERSION, candidateManifestDigest, validateCandidateManifest } from "./finding-adjudication-contract.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["audit-id", "plan", "ledger", "structural", "output"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
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
  const ledger = await verifyLedger({
    planPath: resolve(args.plan),
    ledgerPath: resolve(args.ledger),
    requireFinalized: false,
  });
  if (ledger.plan.audit_id !== args["audit-id"] || structural.audit_id !== args["audit-id"]
    || structural.scope_digest !== ledger.plan.scope_digest) {
    throw new Error("Audit/scope binding mismatch across Plan, Ledger, and structural verification");
  }
  const accepted = acceptedCoverageFindings(structural);
  const candidates = [];
  for (const event of ledger.events.filter(item => item.event_type === "DECISION" && item.result_state === "FINDING")) {
    const check = ledger.plan.checks.find(item => item.check_id === event.check_id);
    if (!check) throw new Error(`Ledger decision references an unknown check: ${event.check_id}`);
    for (const artifact of event.finding_artifacts ?? []) {
      const acceptedFinding = accepted.get(artifact.finding_id);
      if (!acceptedFinding) throw new Error(`Ledger finding is not an accepted structural coverage finding: ${artifact.finding_id}`);
      if (acceptedFinding.primary_check_id !== event.check_id) {
        throw new Error(`Structural primary check mismatch for finding ${artifact.finding_id}`);
      }
      const bytes = await readFile(artifact.path);
      const { finding, finding_object_digest: findingObjectDigest } = parseFindingArtifact(bytes, {
        expectedFindingId: artifact.finding_id,
        auditId: ledger.plan.audit_id,
        scopeDigest: ledger.plan.scope_digest,
        check,
      });
      if (findingObjectDigest !== artifact.finding_object_digest
        || findingObjectDigest !== acceptedFinding.finding_object_digest) {
        throw new Error(`Finding object digest mismatch for ${artifact.finding_id}`);
      }
      candidates.push({
        finding_id: finding.finding_id,
        finding_object_digest: findingObjectDigest,
        primary_check_id: check.check_id,
        artifact: {
          path: artifact.path,
          sha256: artifact.sha256,
          bytes: artifact.bytes,
        },
        source_reports: [acceptedFinding.report_path],
        finding,
      });
    }
  }
  const manifest = {
    schema_version: ADJUDICATION_SCHEMA_VERSION,
    audit_id: ledger.plan.audit_id,
    scope_digest: ledger.plan.scope_digest,
    plan_digest: ledger.plan.manifest_digest,
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
