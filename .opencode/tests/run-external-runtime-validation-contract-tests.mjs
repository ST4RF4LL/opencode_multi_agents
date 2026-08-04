#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { findingObjectDigest } from "../skills/common-subagent/finding-evidence-contract/scripts/finding-contract.mjs";
import {
  buildExternalRuntimeValidationRequest,
  runtimeValidationPacketDigest,
  validateExternalRuntimeValidationRequest,
  validateExternalRuntimeValidationResult,
} from "../skills/common-subagent/finding-evidence-contract/scripts/external-runtime-validation-contract.mjs";

const DIGEST = "a".repeat(64);
const SOURCE_DIGEST = "b".repeat(64);

function finding() {
  return {
    finding_schema_version: 2,
    finding_id: "FIND-RUNTIME-HANDOFF-001",
    audit_id: "runtime-handoff-fixture",
    scope_digest: DIGEST,
    state: "CANDIDATE",
    classification: {
      vulnerability_type_id: "JW-SSRF-01",
      origin_lens: "sink-driven",
      discovery_track: "coverage",
      dimension_claims: [{ dimension: "D6", rationale: "A Java HTTP client crosses an outbound network boundary." }],
    },
    routing: {
      focus_area_id: "FA-001",
      primary_check_id: "check:runtime-handoff",
      domain: "java",
      threat_ids: ["T-001"],
    },
    locations: {
      primary: { file: "src/main/java/Client.java", line_start: 20, source_digest: SOURCE_DIGEST },
    },
    evidence: {
      facts: [{
        kind: "source",
        claim: "A request parameter controls the destination.",
        locator: { file: "src/main/java/Client.java", line_start: 20, source_digest: SOURCE_DIGEST },
        method: "fixture",
        source_digest: SOURCE_DIGEST,
        confidence: "high",
      }, {
        kind: "sink",
        claim: "The destination reaches the Java HTTP client.",
        locator: { file: "src/main/java/Client.java", line_start: 24, source_digest: SOURCE_DIGEST },
        method: "fixture",
        source_digest: SOURCE_DIGEST,
        confidence: "high",
      }],
    },
    reachability: { state: "static-reachable" },
    attacker_influence: { state: "direct" },
    attack_surface: {
      schema_version: 1,
      in_scope: { state: "YES", rationale: "The Java source is frozen in scope.", evidence_fact_indexes: [0] },
      exposure: { state: "AUTHENTICATED", surface: "Java Web request parameter", rationale: "The caller controls a request parameter.", evidence_fact_indexes: [0] },
      vector: { state: "NETWORK", rationale: "The value reaches an outbound network client.", evidence_fact_indexes: [0, 1] },
      auth_scope: { state: "AUTHENTICATED", rationale: "The modeled route requires an application account.", evidence_fact_indexes: [0] },
      preconditions: [{ precondition_id: "PRE-001", description: "The route is deployed.", feasibility: "UNPROVEN", evidence_fact_indexes: [] }],
      identities: { attacker: "authenticated caller", victim: "internal service", effective_principal: "application service identity", evidence_fact_indexes: [0, 1] },
      boundary_crossing: { state: "PROVEN", from: "HTTP request", to: "outbound Java HTTP client", rationale: "The source reaches the sink.", evidence_fact_indexes: [0, 1] },
      impact: { types: ["CONFIDENTIALITY"], outcome: "The application can request an attacker-selected destination.", evidence_fact_indexes: [0, 1] },
      target_reach: { state: "SINGLE_SERVICE", rationale: "One outbound client call is proven.", evidence_fact_indexes: [1] },
      controls: [],
      counterevidence: [],
      blindspots: ["Runtime DNS and egress controls have not been tested."],
      confidence: { level: "medium", rationale: "Static flow is proven; runtime reach is not." },
    },
    guards: [],
    contradictions: [],
    uncertainty: { level: "medium", assumptions: ["Runtime network policy is unknown."] },
    severity: { rationale: "Runtime target reach remains unverified." },
    remediation: { summary: "Allowlist outbound destinations." },
    provenance: { source_report_sha256: "c".repeat(64) },
  };
}

function request() {
  const candidate = finding();
  return buildExternalRuntimeValidationRequest({
    requestId: "RVR-001",
    finding: candidate,
    findingArtifact: { path: "reports/findings/FIND-RUNTIME-HANDOFF-001.json", sha256: "d".repeat(64) },
    decision: {
      finding_id: candidate.finding_id,
      finding_object_digest: findingObjectDigest(candidate),
      state: "SUPPORTED_STATIC",
      decision_rationale: "The request destination reaches the resolved Java HTTP client without a static allowlist.",
      semantic_proof: {
        source_fact_indexes: [0],
        sink_or_config_fact_indexes: [1],
        security_effect: { rationale: "The application attempts an outbound request to a caller-selected destination." },
      },
      blocking_questions: [],
    },
    adjudication: {
      path: "reports/adjudication/security-finding-adjudicator.runtime-handoff-fixture.r1.json",
      sha256: "e".repeat(64),
      json_pointer: "/decisions/0",
    },
    repository: { repository_id: "java-web-fixture", commit: "0123456789abcdef" },
    policy: {
      target_class: "ISOLATED_TEST_ENVIRONMENT",
      allowed_methods: ["INTEGRATION_TEST", "MOCK_SERVER"],
      forbidden_actions: ["PRODUCTION_TARGET", "THIRD_PARTY_TARGET", "REAL_CREDENTIAL_USE", "PERSISTENCE", "DATA_DESTRUCTION"],
      safety_constraints: ["Use only loopback mock services and synthetic inputs."],
      network_access: "LOOPBACK_ONLY",
      credentials: "SYNTHETIC_ONLY",
    },
    exportedBySessionId: "orchestrator-runtime-handoff-r1",
  });
}

function resultFor(requestPacket) {
  const result = {
    schema_version: 1,
    packet_type: "EXTERNAL_RUNTIME_VALIDATION_RESULT",
    request_id: requestPacket.request_id,
    request_packet_digest: requestPacket.packet_digest,
    audit_id: requestPacket.audit_id,
    scope_digest: requestPacket.scope_digest,
    finding_id: requestPacket.finding_id,
    finding_object_digest: requestPacket.finding_object_digest,
    validator: { project: "external-java-web-validator", version: "1.0.0", session_id: "validator-session-001" },
    outcome: "SUPPORTED_RUNTIME",
    methods: [{
      method_id: "METHOD-001",
      kind: "INTEGRATION_TEST",
      description: "Invoke the controller against a loopback mock service.",
      environment: "isolated ephemeral container",
    }],
    observations: [{
      observation_id: "OBS-001",
      claim: "The application issued the caller-selected loopback request.",
      outcome: "CONFIRMS",
      evidence_artifact_ids: ["ART-001"],
    }],
    evidence_artifacts: [{
      artifact_id: "ART-001",
      kind: "sanitized-test-log",
      path: "results/RVR-001/mock-server.json",
      sha256: "f".repeat(64),
      media_type: "application/json",
      sanitized: true,
    }],
    counterevidence: [],
    residual_gaps: [],
    safety_attestation: {
      isolated_test_environment: true,
      production_targets_contacted: false,
      third_party_targets_contacted: false,
      real_credentials_used: false,
      destructive_actions_performed: false,
      notes: [],
    },
  };
  result.packet_digest = runtimeValidationPacketDigest(result);
  return result;
}

async function main() {
  const requestPacket = request();
  assert.deepEqual(validateExternalRuntimeValidationRequest(requestPacket), []);
  const result = resultFor(requestPacket);
  assert.deepEqual(validateExternalRuntimeValidationResult(result, requestPacket), []);

  const unsafe = structuredClone(result);
  unsafe.safety_attestation.production_targets_contacted = true;
  unsafe.packet_digest = runtimeValidationPacketDigest(unsafe);
  assert(validateExternalRuntimeValidationResult(unsafe, requestPacket).includes("runtime-validation-result-safety-attestation-invalid"));

  const detached = structuredClone(result);
  detached.request_packet_digest = "0".repeat(64);
  detached.packet_digest = runtimeValidationPacketDigest(detached);
  assert(validateExternalRuntimeValidationResult(detached, requestPacket).includes("runtime-validation-result-request-digest-mismatch"));

  process.stdout.write(`${JSON.stringify({ complete: true, external_runtime_validation_handoff: "v1", cases: 4 })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
