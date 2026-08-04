#!/usr/bin/env node

import { strict as assert } from "node:assert";
import {
  findingObjectDigest,
  parseFindingArtifact,
  validateFinding,
} from "../skills/common-subagent/finding-evidence-contract/scripts/finding-contract.mjs";
import { deriveCoverageCells } from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-cell-accounting.mjs";

const AUDIT_ID = "finding-contract-fixture";
const SCOPE_DIGEST = "a".repeat(64);
const SOURCE_DIGEST = "b".repeat(64);
const REPORT_DIGEST = "c".repeat(64);
const CHECK = {
  check_id: "check:fixture",
  focus_area_id: "FA-001",
  domain: "java",
  vulnerability_type_id: "JW-AUTHN-01",
  lens: "sink-driven",
  dimensions: ["D2"],
};

function attackSurface() {
  return {
    schema_version: 1,
    in_scope: { state: "YES", rationale: "The affected Java source is in the frozen audit scope.", evidence_fact_indexes: [0] },
    exposure: { state: "PUBLIC", surface: "HTTP Authorization header", rationale: "The value enters through a public request boundary.", evidence_fact_indexes: [0] },
    vector: { state: "NETWORK", rationale: "The request can be supplied over the application network interface.", evidence_fact_indexes: [0] },
    auth_scope: { state: "UNAUTHENTICATED", rationale: "The token is parsed before an authenticated identity is established.", evidence_fact_indexes: [0, 1] },
    preconditions: [{
      precondition_id: "PRE-001",
      description: "The HTTP authentication endpoint is deployed and reachable.",
      feasibility: "UNPROVEN",
      evidence_fact_indexes: [],
    }],
    identities: {
      attacker: "remote unauthenticated caller",
      victim: "application user",
      effective_principal: "identity derived from the supplied token",
      evidence_fact_indexes: [0, 1],
    },
    boundary_crossing: {
      state: "PROVEN",
      from: "untrusted HTTP request",
      to: "authentication identity context",
      rationale: "The supplied header reaches the token parser.",
      evidence_fact_indexes: [0, 1],
    },
    impact: {
      types: ["AUTHORIZATION", "INTEGRITY"],
      outcome: "An invalid token may establish an attacker-selected identity.",
      evidence_fact_indexes: [0, 1],
    },
    target_reach: {
      state: "SINGLE_USER",
      rationale: "The static evidence supports one forged identity per request.",
      evidence_fact_indexes: [1],
    },
    controls: [],
    counterevidence: [],
    blindspots: ["Runtime gateway and deployment controls were not tested."],
    confidence: { level: "medium", rationale: "The source path is proven, while deployment exposure remains unverified." },
  };
}

function candidate(overrides = {}) {
  return {
    finding_schema_version: 2,
    finding_id: "FIND-001",
    audit_id: AUDIT_ID,
    scope_digest: SCOPE_DIGEST,
    state: "CANDIDATE",
    classification: {
      vulnerability_type_id: CHECK.vulnerability_type_id,
      origin_lens: CHECK.lens,
      discovery_track: "coverage",
      dimension_claims: [{ dimension: "D2", rationale: "Authentication control is affected." }],
    },
    routing: {
      focus_area_id: CHECK.focus_area_id,
      primary_check_id: CHECK.check_id,
      domain: CHECK.domain,
      threat_ids: ["T-001"],
    },
    locations: {
      primary: { file: "src/Auth.java", line_start: 42, line_end: 44, source_digest: SOURCE_DIGEST },
    },
    evidence: {
      facts: [
        {
          kind: "source",
          claim: "Authorization header is attacker-controlled input.",
          locator: { file: "src/Auth.java", line_start: 42, source_digest: SOURCE_DIGEST },
          method: "manual-source",
          source_digest: SOURCE_DIGEST,
          confidence: "high",
        },
        {
          kind: "sink",
          claim: "The token parser accepts the value at the authentication boundary.",
          locator: { file: "src/Auth.java", line_start: 44, source_digest: SOURCE_DIGEST },
          method: "manual-source",
          source_digest: SOURCE_DIGEST,
          confidence: "high",
        },
      ],
    },
    reachability: { state: "static-reachable" },
    attacker_influence: { state: "direct" },
    attack_surface: attackSurface(),
    guards: [],
    contradictions: [],
    uncertainty: { level: "medium", assumptions: ["Runtime deployment has not been tested."] },
    severity: { rationale: "Reachable authentication boundary with direct attacker input." },
    remediation: { summary: "Verify the token before using claims." },
    provenance: { source_report_sha256: REPORT_DIGEST },
    ...overrides,
  };
}

function expectError(errors, expected) {
  assert(errors.includes(expected), `Expected ${expected}; got ${errors.join(", ")}`);
}

async function main() {
  const valid = candidate();
  assert.deepEqual(validateFinding(valid, {
    expectedFindingId: valid.finding_id,
    auditId: AUDIT_ID,
    scopeDigest: SCOPE_DIGEST,
    check: CHECK,
  }), []);

  const otherDimension = candidate({
    classification: {
      ...valid.classification,
      dimension_claims: [{ dimension: "D7", rationale: "Incorrect classification should be rejected." }],
    },
  });
  expectError(validateFinding(otherDimension, { check: CHECK }), "finding-dimension-not-in-check");

  const missingSemanticAnchor = candidate({ evidence: { facts: [valid.evidence.facts[0]] } });
  expectError(validateFinding(missingSemanticAnchor), "evidence-semantic-anchor-missing");

  const missingAttackSurface = candidate({ attack_surface: undefined });
  expectError(validateFinding(missingAttackSurface), "attack-surface-missing");

  const outOfRangeAttackSurface = candidate({
    attack_surface: {
      ...attackSurface(),
      impact: { ...attackSurface().impact, evidence_fact_indexes: [99] },
    },
  });
  expectError(validateFinding(outOfRangeAttackSurface), "attack-surface-impact-invalid");

  const rejectedState = candidate({ state: "REJECTED" });
  expectError(validateFinding(rejectedState, { check: CHECK }), "finding-state-not-admissible-for-ledger");

  const manualScore = candidate({ severity: { rationale: "Fixture", base_score: 9.8 } });
  expectError(validateFinding(manualScore), "severity-manual-score-forbidden");

  const provisional = candidate({ severity: {
    rationale: "Fixture",
    cvss: { assessment_state: "PROVISIONAL", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
  } });
  assert.deepEqual(validateFinding(provisional), []);

  const parsed = parseFindingArtifact(Buffer.from(`${JSON.stringify(valid)}\n`), {
    expectedFindingId: valid.finding_id,
    auditId: AUDIT_ID,
    scopeDigest: SCOPE_DIGEST,
    check: CHECK,
  });
  assert.equal(parsed.finding_object_digest, findingObjectDigest(valid));
  assert.throws(() => parseFindingArtifact("not-json"), /JSON object/);

  const singleDimensionFindingReport = {
    audit_strategy: "sink-driven",
    scope: {
      scope_digest: SCOPE_DIGEST,
      assigned_file_ids: ["file:fixture"],
      assigned_function_ids: [],
      assigned_catalog_ids: [],
    },
    file_coverage: [{
      file_id: "file:fixture",
      status: "FINDING",
      finding_ids: [valid.finding_id],
    }],
    function_coverage: [],
    catalog_coverage: [],
    findings: [valid],
  };
  const cells = new Map(deriveCoverageCells(singleDimensionFindingReport, new Map())
    .map(cell => [cell.dimension, cell]));
  assert.deepEqual(cells.get("D2")?.finding_ids, [valid.finding_id]);
  assert.equal(cells.get("D2")?.status, "FINDING");
  assert.equal(cells.get("D1")?.status, "PASS");
  assert.deepEqual(cells.get("D1")?.finding_ids, []);

  process.stdout.write(`${JSON.stringify({ complete: true, finding_contract: "v2+attack-surface-v1", cases: 10 })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
