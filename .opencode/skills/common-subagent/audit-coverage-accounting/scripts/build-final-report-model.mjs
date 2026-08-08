#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { objectDigest } from "./coverage-v2-common.mjs";
import { validateAdjudicationManifest } from "../../finding-adjudication/scripts/finding-adjudication-contract.mjs";
import { validateCvssAssessmentManifest } from "../../finding-adjudication/scripts/cvss-assessment-contract.mjs";
import { validateAttackChainManifest } from "../../../attack-chain-subagent/system-attack-chain-hunting/scripts/attack-chain-contract.mjs";
import { finalReportModelDigest, validateFinalReportModel } from "./final-report-model-core.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["audit-id", "mode", "coverage-summary", "adjudication-input", "adjudication", "cvss", "chains", "output"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  }
  if (!new Set(["final", "policy-final", "partial-final", "checkpoint"]).has(args.mode)) {
    throw new Error("--mode must be final, policy-final, partial-final, or checkpoint");
  }
  return args;
}

function source(artifact, digest, jsonPointer) {
  return { artifact, digest, json_pointer: jsonPointer };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [summary, input, adjudication, cvss, chains] = await Promise.all([
    readFile(resolve(args["coverage-summary"]), "utf8").then(JSON.parse),
    readFile(resolve(args["adjudication-input"]), "utf8").then(JSON.parse),
    readFile(resolve(args.adjudication), "utf8").then(JSON.parse),
    readFile(resolve(args.cvss), "utf8").then(JSON.parse),
    readFile(resolve(args.chains), "utf8").then(JSON.parse),
  ]);
  if (summary.audit_id !== args["audit-id"] || summary.manifest_digest !== objectDigest(summary)) {
    throw new Error("Coverage summary is invalid or bound to another audit");
  }
  if ((args.mode === "final" && summary.coverage_status !== "COMPLETE")
    || (args.mode === "policy-final" && summary.policy_satisfied !== true)
    || (args.mode === "partial-final" && (summary.coverage_status !== "PARTIAL" || summary.seal_state !== "FINALIZED_PARTIAL"))
    || (args.mode === "checkpoint" && summary.coverage_status !== "PARTIAL")) {
    throw new Error("Report mode does not match the verified coverage status");
  }
  const adjudicationErrors = validateAdjudicationManifest(adjudication, input);
  if (adjudicationErrors.length > 0) throw new Error(`Finding adjudication is invalid:\n- ${adjudicationErrors.join("\n- ")}`);
  const cvssErrors = validateCvssAssessmentManifest(cvss, adjudication);
  if (cvssErrors.length > 0) throw new Error(`CVSS assessment is invalid:\n- ${cvssErrors.join("\n- ")}`);
  const chainErrors = validateAttackChainManifest(chains, adjudication);
  if (chainErrors.length > 0) throw new Error(`Attack-chain manifest is invalid:\n- ${chainErrors.join("\n- ")}`);
  if (chains.audit_id !== args["audit-id"] || chains.scope_digest !== summary.scope_digest) {
    throw new Error("Attack-chain report is bound to a different audit or scope");
  }
  const decisionSource = index => source(resolve(args.adjudication), adjudication.manifest_digest, `/decisions/${index}`);
  const attackSurfaceReviewSource = index => source(resolve(args.adjudication), adjudication.manifest_digest, `/decisions/${index}/attack_surface_review`);
  const candidateSource = index => source(resolve(args["adjudication-input"]), input.manifest_digest, `/candidates/${index}/finding/attack_surface`);
  const cvssSource = index => source(resolve(args.cvss), cvss.manifest_digest, `/assessments/${index}`);
  const chainSource = index => source(resolve(args.chains), chains.manifest_digest, `/chains/${index}`);
  const metrics = [
    ["coverage.all_atomic_checks", summary.accounting.known_coverage, "/accounting/known_coverage"],
    ["coverage.vulnerability_type_checks", summary.vulnerability_types.checks, "/vulnerability_types/checks"],
    ["coverage.external_interface_checks", summary.external_interfaces.known_checks, "/external_interfaces/known_checks"],
    ["coverage.file_checks", summary.files.checks, "/files/checks"],
    ["coverage.function_checks", summary.functions.checks, "/functions/checks"],
    ["coverage.assignment_units", summary.execution?.assignment_units, "/execution/assignment_units"],
    ["coverage.attested_checks", summary.evidence?.attested_checks, "/evidence/attested_checks"],
  ].map(([metric_id, value, pointer]) => ({
    metric_id,
    value,
    source: source(resolve(args["coverage-summary"]), summary.manifest_digest, pointer),
  }));
  const findings = [];
  const excludedFindings = [];
  const cvssByFindingId = new Map(cvss.assessments.map((assessment, index) => [assessment.finding_id, { assessment, index }]));
  const candidatesByFindingId = new Map(input.candidates.map((candidate, index) => [candidate.finding_id, { candidate, index }]));
  adjudication.decisions.forEach((decision, index) => {
    const candidateRecord = candidatesByFindingId.get(decision.finding_id);
    if (!candidateRecord) throw new Error(`Adjudication decision has no bound candidate: ${decision.finding_id}`);
    const row = {
      finding_id: decision.finding_id,
      state: decision.state,
      finding_object_digest: decision.finding_object_digest,
      source: decisionSource(index),
      attack_surface: structuredClone(candidateRecord.candidate.finding.attack_surface),
      attack_surface_source: candidateSource(candidateRecord.index),
      attack_surface_review: structuredClone(decision.attack_surface_review),
      attack_surface_review_source: attackSurfaceReviewSource(index),
    };
    if (["SUPPORTED_STATIC", "SUPPORTED_RUNTIME"].includes(decision.state)) {
      const score = cvssByFindingId.get(decision.finding_id);
      if (!score) throw new Error(`Supported finding is missing a CVSS assessment: ${decision.finding_id}`);
      row.cvss = {
        vector: score.assessment.vector,
        base_score: score.assessment.base_score,
        severity: score.assessment.severity,
        source: cvssSource(score.index),
      };
      findings.push(row);
    }
    else excludedFindings.push(row);
  });
  const acceptedChains = [];
  const rejectedChains = [];
  chains.chains.forEach((chain, index) => {
    const row = {
      chain_id: chain.chain_id,
      assessment_state: chain.assessment_state,
      first_blocking_step_id: chain.first_blocking_step_id,
      source: chainSource(index),
    };
    if (chain.assessment_state === "CONTRADICTED") rejectedChains.push(row);
    else acceptedChains.push(row);
  });
  const model = {
    schema_version: 1,
    audit_id: args["audit-id"],
    scope_digest: summary.scope_digest,
    report_kind: args.mode === "final" ? "FINAL"
      : args.mode === "policy-final" ? "POLICY_FINAL"
        : args.mode === "partial-final" ? "PARTIAL_FINAL" : "CHECKPOINT",
    coverage: {
      summary_digest: summary.manifest_digest,
      coverage_status: summary.coverage_status,
      seal_state: summary.seal_state,
      policy_mode: summary.policy_mode ?? "assurance",
      policy_satisfied: summary.policy_satisfied === true,
      metrics,
    },
    inputs: {
      coverage_summary: resolve(args["coverage-summary"]),
      adjudication_input: resolve(args["adjudication-input"]),
      adjudication: resolve(args.adjudication),
      cvss_assessment: resolve(args.cvss),
      attack_chains: resolve(args.chains),
    },
    findings: findings.sort((left, right) => left.finding_id.localeCompare(right.finding_id)),
    excluded_findings: excludedFindings.sort((left, right) => left.finding_id.localeCompare(right.finding_id)),
    chains: acceptedChains.sort((left, right) => left.chain_id.localeCompare(right.chain_id)),
    rejected_chains: rejectedChains.sort((left, right) => left.chain_id.localeCompare(right.chain_id)),
  };
  model.manifest_digest = finalReportModelDigest(model);
  const errors = validateFinalReportModel(model);
  if (errors.length > 0) throw new Error(`Final report model is invalid:\n- ${errors.join("\n- ")}`);
  const output = resolve(args.output);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(model, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output, audit_id: model.audit_id, findings: model.findings.length, chains: model.chains.length })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
