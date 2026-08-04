#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { findingObjectDigest } from "../skills/common-subagent/finding-evidence-contract/scripts/finding-contract.mjs";
import {
  candidateManifestDigest,
  validateAdjudicationManifest,
  validateCandidateManifest,
} from "../skills/common-subagent/finding-adjudication/scripts/finding-adjudication-contract.mjs";

const AUDIT_ID = "finding-adjudication-fixture";
const SCOPE_DIGEST = "a".repeat(64);
const PLAN_DIGEST = "b".repeat(64);
const STRUCTURAL_DIGEST = "c".repeat(64);
const SOURCE_DIGEST = "d".repeat(64);
const REPORT_DIGEST = "e".repeat(64);

function finding() {
  return {
    finding_schema_version: 2,
    finding_id: "FIND-ADJ-001",
    audit_id: AUDIT_ID,
    scope_digest: SCOPE_DIGEST,
    state: "CANDIDATE",
    classification: {
      vulnerability_type_id: "JW-SSRF-01",
      origin_lens: "sink-driven",
      discovery_track: "coverage",
      dimension_claims: [{ dimension: "D6", rationale: "The candidate claims an outbound request security boundary." }],
    },
    routing: {
      focus_area_id: "FA-001",
      primary_check_id: "check:fixture",
      domain: "java",
      threat_ids: ["T-001"],
    },
    locations: {
      primary: { file: "src/Client.java", line_start: 40, source_digest: SOURCE_DIGEST },
    },
    evidence: {
      facts: [
        {
          kind: "source",
          claim: "The request argument is supplied by the caller.",
          locator: { file: "src/Client.java", line_start: 40, source_digest: SOURCE_DIGEST },
          method: "fixture",
          source_digest: SOURCE_DIGEST,
          confidence: "high",
        },
        {
          kind: "sink",
          claim: "The value is passed to an HTTP client invocation.",
          locator: { file: "src/Client.java", line_start: 42, source_digest: SOURCE_DIGEST },
          method: "fixture",
          source_digest: SOURCE_DIGEST,
          confidence: "high",
        },
      ],
    },
    reachability: { state: "static-reachable" },
    attacker_influence: { state: "direct" },
    attack_surface: {
      schema_version: 1,
      in_scope: { state: "YES", rationale: "The Java client is in the frozen audit scope.", evidence_fact_indexes: [0] },
      exposure: { state: "AUTHENTICATED", surface: "Java web request parameter", rationale: "A caller-controlled value reaches the client.", evidence_fact_indexes: [0] },
      vector: { state: "NETWORK", rationale: "The claimed target is selected through a network request.", evidence_fact_indexes: [0, 1] },
      auth_scope: { state: "AUTHENTICATED", rationale: "The fixture models an authenticated application caller.", evidence_fact_indexes: [0] },
      preconditions: [{
        precondition_id: "PRE-001",
        description: "The caller can select the destination argument.",
        feasibility: "PLAUSIBLE",
        evidence_fact_indexes: [0],
      }],
      identities: {
        attacker: "authenticated application caller",
        victim: "internal HTTP service",
        effective_principal: "application service credential",
        evidence_fact_indexes: [0, 1],
      },
      boundary_crossing: {
        state: "PROVEN",
        from: "application request",
        to: "outbound network client",
        rationale: "Caller input reaches the HTTP client invocation.",
        evidence_fact_indexes: [0, 1],
      },
      impact: {
        types: ["CONFIDENTIALITY"],
        outcome: "The service may issue a request to an attacker-selected destination.",
        evidence_fact_indexes: [0, 1],
      },
      target_reach: {
        state: "SINGLE_SERVICE",
        rationale: "Static evidence proves one outbound client invocation.",
        evidence_fact_indexes: [1],
      },
      controls: [],
      counterevidence: [],
      blindspots: ["Runtime egress policy is not represented in the fixture."],
      confidence: { level: "medium", rationale: "Source and sink are static; deployment controls are unknown." },
    },
    guards: [],
    contradictions: [],
    uncertainty: { level: "medium", assumptions: ["Runtime egress controls are not tested."] },
    severity: { rationale: "Only an adjudicator can establish destination reachability." },
    remediation: { summary: "Allowlist destinations before dispatch." },
    provenance: { source_report_sha256: REPORT_DIGEST },
  };
}

function decision(overrides = {}) {
  return {
    finding_id: "FIND-ADJ-001",
    finding_object_digest: findingObjectDigest(finding()),
    state: "SUPPORTED_STATIC",
    decision_rationale: "The resolved client API performs the outbound request and the tested allowlist counterclaim is absent.",
    attack_surface_review: {
      disposition: "LIMITED",
      reviewed_fields: ["in_scope", "exposure", "vector", "auth_scope", "preconditions", "identities", "boundary_crossing", "impact", "target_reach", "controls", "counterevidence", "blindspots", "confidence"],
      rationale: "The static Java call path and identity transition are supported, while deployment egress remains unknown.",
      evidence: ["Finding evidence facts 0 and 1 plus the deployment-guard search were reviewed."],
      limitations: ["Runtime DNS resolution and egress policy were not observed."],
    },
    semantic_proof: {
      source_fact_indexes: [0],
      sink_or_config_fact_indexes: [1],
      framework: {
        component: "fixture-http-client",
        version_or_commit: "fixture-1.0.0",
        api_or_configuration: "FixtureClient.send(String)",
        evidence: ["Dependency lock and resolved method signature were reviewed."],
      },
      path: {
        state: "PROVEN",
        steps: ["Caller input reaches the request argument.", "FixtureClient.send dispatches an outbound request."],
      },
      security_effect: {
        state: "PROVEN",
        rationale: "An attacker-controlled destination reaches the outbound HTTP client.",
      },
    },
    guards: ["local", "inherited", "global", "deployment"].map(scope => ({
      scope,
      state: "ABSENT",
      effective_for_claim: false,
      rationale: `Fixture has no ${scope} allowlist guard.`,
      evidence: [`${scope} guard search completed.`],
    })),
    counterclaim: {
      claim: "An effective destination allowlist blocks attacker-controlled targets.",
      outcome: "REFUTED",
      evidence: ["No configured or inherited allowlist reaches FixtureClient.send."],
    },
    contradiction_refs: [],
    blocking_questions: [],
    ...overrides,
  };
}

function manifestWith(decisions) {
  const candidate = finding();
  const input = {
    schema_version: 1,
    audit_id: AUDIT_ID,
    scope_digest: SCOPE_DIGEST,
    plan_digest: PLAN_DIGEST,
    structural_digest: STRUCTURAL_DIGEST,
    candidates: [{
      finding_id: candidate.finding_id,
      finding_object_digest: findingObjectDigest(candidate),
      primary_check_id: candidate.routing.primary_check_id,
      artifact: { path: "/fixture/finding.json", sha256: "f".repeat(64), bytes: 1 },
      source_reports: ["/fixture/report.json"],
      finding: candidate,
    }],
  };
  input.manifest_digest = candidateManifestDigest(input);
  const output = {
    schema_version: 1,
    audit_id: AUDIT_ID,
    scope_digest: SCOPE_DIGEST,
    input_manifest_digest: input.manifest_digest,
    adjudicator_session_id: "adjudicator-fixture-r1",
    decisions,
  };
  output.manifest_digest = candidateManifestDigest(output);
  return { input, output };
}

function expectError(errors, expected) {
  assert(errors.some(error => error.endsWith(expected)), `Expected ${expected}; got ${errors.join(", ")}`);
}

async function main() {
  const valid = manifestWith([decision()]);
  assert.deepEqual(validateCandidateManifest(valid.input), []);
  assert.deepEqual(validateAdjudicationManifest(valid.output, valid.input), []);

  const unsupported = manifestWith([decision({ counterclaim: {
    ...decision().counterclaim,
    outcome: "UNRESOLVED",
  } })]);
  expectError(validateAdjudicationManifest(unsupported.output, unsupported.input), "supported-decision-counterclaim-not-refuted");

  const unreviewedSurface = manifestWith([decision({
    attack_surface_review: {
      ...decision().attack_surface_review,
      reviewed_fields: ["exposure"],
    },
  })]);
  expectError(validateAdjudicationManifest(unreviewedSurface.output, unreviewedSurface.input), "attack-surface-review-fields-incomplete");

  const rejected = manifestWith([decision({
    state: "REJECTED",
    decision_rationale: "The presumed HTTP client call is only a DTO constructor.",
    counterclaim: {
      claim: "The API is a DTO constructor rather than an outbound HTTP sink.",
      outcome: "SUPPORTED",
      evidence: ["Resolved FixtureClient constructor has no network dispatch."],
    },
    rejection_reason: "wrong-semantic-sink",
  })]);
  assert.deepEqual(validateAdjudicationManifest(rejected.output, rejected.input), []);

  const missing = manifestWith([]);
  expectError(validateAdjudicationManifest(missing.output, missing.input), "missing");

  process.stdout.write(`${JSON.stringify({ complete: true, finding_adjudication: "v1", cases: 5 })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
