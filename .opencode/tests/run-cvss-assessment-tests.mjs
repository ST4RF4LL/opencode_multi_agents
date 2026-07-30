#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { scoreCvssV31 } from "../skills/common-subagent/finding-evidence-contract/scripts/cvss-v31.mjs";
import {
  buildCvssAssessmentManifest,
  validateCvssAssessmentClaims,
  validateCvssAssessmentManifest,
} from "../skills/common-subagent/finding-adjudication/scripts/cvss-assessment-contract.mjs";
import { candidateManifestDigest } from "../skills/common-subagent/finding-adjudication/scripts/finding-adjudication-contract.mjs";

const DIGEST = "a".repeat(64);
const FINDING_ID = "FIND-CVSS-001";

function adjudication() {
  const value = {
    schema_version: 1,
    audit_id: "cvss-fixture",
    scope_digest: DIGEST,
    input_manifest_digest: "b".repeat(64),
    adjudicator_session_id: "cvss-fixture-r1",
    decisions: [{
      finding_id: FINDING_ID,
      finding_object_digest: "c".repeat(64),
      state: "SUPPORTED_STATIC",
    }, {
      finding_id: "FIND-CVSS-REJECTED",
      finding_object_digest: "d".repeat(64),
      state: "REJECTED",
    }],
  };
  value.manifest_digest = candidateManifestDigest(value);
  return value;
}

function claims(adjudicationManifest) {
  return {
    schema_version: 1,
    audit_id: adjudicationManifest.audit_id,
    scope_digest: adjudicationManifest.scope_digest,
    adjudication_manifest_digest: adjudicationManifest.manifest_digest,
    assessments: [{
      finding_id: FINDING_ID,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      rationale: "The fixture has a remotely reachable, fully compromising static effect.",
      assumptions: ["The documented network listener is deployed."],
      evidence_refs: ["decision:0", "fixture-source"],
    }],
  };
}

async function main() {
  const critical = scoreCvssV31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  assert.deepEqual(critical, {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    base_score: 9.8,
    severity: "Critical",
  });
  assert.throws(() => scoreCvssV31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"), /every base metric/);
  assert.throws(() => scoreCvssV31("CVSS:3.1/AV:N/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), /duplicate/);

  const adjudicationManifest = adjudication();
  const validClaims = claims(adjudicationManifest);
  assert.deepEqual(validateCvssAssessmentClaims(validClaims, adjudicationManifest), []);
  const manifest = buildCvssAssessmentManifest(validClaims, adjudicationManifest);
  assert.deepEqual(validateCvssAssessmentManifest(manifest, adjudicationManifest), []);

  const manual = claims(adjudicationManifest);
  manual.assessments[0].base_score = 10;
  assert(validateCvssAssessmentClaims(manual, adjudicationManifest).some(error => error.endsWith("manual-score-forbidden")));
  const rejected = claims(adjudicationManifest);
  rejected.assessments[0].finding_id = "FIND-CVSS-REJECTED";
  assert(validateCvssAssessmentClaims(rejected, adjudicationManifest).some(error => error.endsWith("finding-not-supported")));

  process.stdout.write(`${JSON.stringify({ complete: true, cvss: "3.1", cases: 6 })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
