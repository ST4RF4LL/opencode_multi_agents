#!/usr/bin/env node

import { strict as assert } from "node:assert";
import {
  threatModelDigest,
  validateThreatModel,
} from "../skills/threat-modeling-subagent/evidence-backed-threat-modeling/scripts/threat-model-contract.mjs";

const DIGEST = "a".repeat(64);

function fixture() {
  const model = {
    schema_version: 1,
    audit_id: "threat-contract-fixture",
    scope_digest: DIGEST,
    mode: "bootstrap",
    system_context: "A Java Web application with one authenticated record endpoint.",
    assets: [{ asset_id: "ASSET-001", name: "tenant record", sensitivity: "high", evidence: [{ fixture: true }] }],
    actors: [{ actor_id: "ACTOR-001", type: "remote_auth", capabilities: ["call endpoint"], evidence: [{ fixture: true }] }],
    trust_boundaries: [{ trust_boundary_id: "TB-001", from: "HTTP request", to: "Java service", evidence: [{ fixture: true }] }],
    entry_points: [{ entry_point_id: "EP-001", name: "record endpoint", trust_boundary_ids: ["TB-001"], reachable_asset_ids: ["ASSET-001"], inventory_ids: ["route:record"], evidence: [{ fixture: true }] }],
    threats: [{
      threat_id: "T-001",
      outcome: "A tenant reads another tenant's sensitive record.",
      actor_ids: ["ACTOR-001"],
      entry_point_ids: ["EP-001"],
      trust_boundary_ids: ["TB-001"],
      asset_ids: ["ASSET-001"],
      dimensions: ["D3"],
      impact: "high",
      likelihood: "possible",
      status: "unmitigated",
      controls: [],
      evidence: [{ fixture: true }],
      provenance_tags: ["code-verified"],
    }],
    security_invariants: [{
      invariant_id: "INV-001",
      statement: "A tenant may access only records owned by that tenant.",
      asset_ids: ["ASSET-001"],
      threat_ids: ["T-001"],
      enforcement_points: ["Java service ownership check"],
      evidence: [{ fixture: true }],
      provenance_tags: ["code-verified"],
    }],
    assumptions: [{
      assumption_id: "ASM-001",
      statement: "The gateway passes the authenticated tenant identity unchanged.",
      category: "deployment",
      status: "UNVERIFIED",
      affects_threat_ids: ["T-001"],
      evidence: [],
      provenance_tags: ["deployment-unknown"],
    }],
    attacker_stories: [{
      story_id: "STORY-001",
      actor_id: "ACTOR-001",
      entry_point_id: "EP-001",
      threat_id: "T-001",
      affected_asset_ids: ["ASSET-001"],
      preconditions: ["The attacker has a tenant account."],
      steps: ["Submit another tenant's record ID.", "Reach the record lookup without an ownership check."],
      outcome: "The endpoint returns another tenant's record.",
      evidence: [{ fixture: true }],
      provenance_tags: ["code-verified"],
    }],
    out_of_scope_stories: [{
      story_id: "OOS-001",
      scenario: "Compromise of the managed identity provider.",
      reason: "The provider is outside the frozen source and deployment scope.",
      reconsider_when: ["Identity-provider configuration enters scope."],
      evidence: [{ fixture: true }],
      provenance_tags: ["deployment-unknown"],
    }],
    severity_calibration: {
      model: "contextual-four-level-v1",
      context_notes: ["Final CVSS is derived only after finding adjudication."],
      evidence: [{ fixture: true }],
      levels: [
        { severity: "CRITICAL", criteria: ["Broad administrative or cross-tenant compromise."], examples: [{ scenario: "All tenant records are enumerable.", rationale: "Broad sensitive-data exposure.", threat_ids: ["T-001"] }], not_applicable_reason: null },
        { severity: "HIGH", criteria: ["Repeatable access to selected cross-tenant records."], examples: [{ scenario: "A chosen cross-tenant record is returned.", rationale: "Direct sensitive-data exposure.", threat_ids: ["T-001"] }], not_applicable_reason: null },
        { severity: "MEDIUM", criteria: ["Only nonsensitive metadata is exposed."], examples: [{ scenario: "Record existence is disclosed.", rationale: "Constrained confidentiality impact.", threat_ids: ["T-001"] }], not_applicable_reason: null },
        { severity: "LOW", criteria: ["Only a minor observable difference remains."], examples: [{ scenario: "A rejected ID changes an error string.", rationale: "Minimal security effect.", threat_ids: ["T-001"] }], not_applicable_reason: null },
      ],
    },
    deprioritized: [],
    history_clusters: [],
    entry_point_coverage: [{ entry_point_id: "EP-001", status: "THREAT", threat_ids: ["T-001"], reason: null, evidence: [{ fixture: true }] }],
    open_questions: [],
    provenance: { target: "fixture", commit: "fixture", inputs: ["test"], owner: null },
  };
  model.manifest_digest = threatModelDigest(model);
  return model;
}

function expectError(errors, expected) {
  assert(errors.includes(expected), `Expected ${expected}; got ${errors.join(", ")}`);
}

async function main() {
  const valid = fixture();
  assert.deepEqual(validateThreatModel(valid), []);

  const missingStory = fixture();
  missingStory.attacker_stories = [];
  missingStory.manifest_digest = threatModelDigest(missingStory);
  expectError(validateThreatModel(missingStory), "threat:T-001:attacker-story-missing");

  const incompleteCalibration = fixture();
  incompleteCalibration.severity_calibration.levels = incompleteCalibration.severity_calibration.levels.slice(0, 3);
  incompleteCalibration.manifest_digest = threatModelDigest(incompleteCalibration);
  expectError(validateThreatModel(incompleteCalibration), "severity-calibration-levels-invalid");

  const tampered = fixture();
  tampered.system_context = "tampered";
  expectError(validateThreatModel(tampered), "threat-model-digest-invalid");

  process.stdout.write(`${JSON.stringify({ complete: true, threat_model_contract: "v1-rich", cases: 4 })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
