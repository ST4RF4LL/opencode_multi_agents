import { createHash } from "node:crypto";
import {
  findingObjectDigest,
  validateAttackSurface,
  validateFinding,
} from "./finding-contract.mjs";

export const RUNTIME_VALIDATION_HANDOFF_SCHEMA_VERSION = 1;

const REQUEST_TYPE = "EXTERNAL_RUNTIME_VALIDATION_REQUEST";
const RESULT_TYPE = "EXTERNAL_RUNTIME_VALIDATION_RESULT";
const STATIC_STATES = new Set(["SUPPORTED_STATIC", "INCONCLUSIVE"]);
const RESULT_OUTCOMES = new Set(["SUPPORTED_RUNTIME", "REJECTED", "INCONCLUSIVE", "NOT_RUN"]);
const METHOD_KINDS = new Set([
  "UNIT_TEST",
  "INTEGRATION_TEST",
  "INSTRUMENTED_HARNESS",
  "MOCK_SERVER",
  "BROWSER_TEST",
  "CONTAINER_TEST",
  "OTHER",
]);
const OBSERVATION_OUTCOMES = new Set(["CONFIRMS", "CONTRADICTS", "NEUTRAL"]);
const NETWORK_POLICIES = new Set(["DENY", "LOOPBACK_ONLY", "TEST_FIXTURE_ONLY"]);
const CREDENTIAL_POLICIES = new Set(["NONE", "SYNTHETIC_ONLY"]);
const REQUIRED_FORBIDDEN_ACTIONS = [
  "PRODUCTION_TARGET",
  "THIRD_PARTY_TARGET",
  "REAL_CREDENTIAL_USE",
  "PERSISTENCE",
  "DATA_DESTRUCTION",
];

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function validDigest(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function uniqueStrings(value, { required = false } = {}) {
  return Array.isArray(value)
    && (!required || value.length > 0)
    && value.every(nonEmptyString)
    && new Set(value).size === value.length;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
}

export function runtimeValidationPacketDigest(packet) {
  const copy = structuredClone(packet);
  delete copy.packet_digest;
  return createHash("sha256").update(JSON.stringify(canonicalize(copy))).digest("hex");
}

function validArtifact(artifact) {
  return isObject(artifact)
    && nonEmptyString(artifact.path)
    && validDigest(artifact.sha256);
}

function validIndexes(value, { required = false } = {}) {
  return Array.isArray(value)
    && (!required || value.length > 0)
    && value.every(index => Number.isInteger(index) && index >= 0)
    && new Set(value).size === value.length;
}

export function buildExternalRuntimeValidationRequest({
  requestId,
  finding,
  findingArtifact,
  decision,
  adjudication,
  repository,
  policy,
  proofGaps,
  exportedBySessionId,
}) {
  const findingErrors = validateFinding(finding);
  if (findingErrors.length > 0) throw new Error(`Finding is invalid: ${findingErrors.join(", ")}`);
  if (!isObject(decision) || decision.finding_id !== finding.finding_id
    || decision.finding_object_digest !== findingObjectDigest(finding)
    || !STATIC_STATES.has(decision.state)) {
    throw new Error("Decision is not a supported static/inconclusive assessment of the supplied finding");
  }
  const packet = {
    schema_version: RUNTIME_VALIDATION_HANDOFF_SCHEMA_VERSION,
    packet_type: REQUEST_TYPE,
    request_id: requestId,
    audit_id: finding.audit_id,
    scope_digest: finding.scope_digest,
    finding_id: finding.finding_id,
    finding_object_digest: findingObjectDigest(finding),
    static_assessment: {
      state: decision.state,
      decision_rationale: decision.decision_rationale,
      adjudication_artifact: structuredClone(adjudication),
    },
    source_binding: {
      repository_id: repository?.repository_id,
      commit: repository?.commit,
      finding_artifact: structuredClone(findingArtifact),
      primary_location: structuredClone(finding.locations.primary),
    },
    attack_surface: structuredClone(finding.attack_surface),
    claim: {
      vulnerability_type_id: finding.classification.vulnerability_type_id,
      summary: decision.decision_rationale,
      expected_security_effect: decision.semantic_proof?.security_effect?.rationale,
      source_fact_indexes: structuredClone(decision.semantic_proof?.source_fact_indexes ?? []),
      sink_or_config_fact_indexes: structuredClone(decision.semantic_proof?.sink_or_config_fact_indexes ?? []),
    },
    proof_gaps: structuredClone(proofGaps ?? decision.blocking_questions ?? []),
    validation_policy: structuredClone(policy),
    provenance: {
      producer: "opencode-multi-agents-static-audit",
      exported_by_session_id: exportedBySessionId,
    },
  };
  if (packet.proof_gaps.length === 0) {
    packet.proof_gaps.push("Runtime behavior has not been observed in an isolated test environment.");
  }
  packet.packet_digest = runtimeValidationPacketDigest(packet);
  const errors = validateExternalRuntimeValidationRequest(packet);
  if (errors.length > 0) throw new Error(`Runtime-validation request is invalid: ${errors.join(", ")}`);
  return packet;
}

export function validateExternalRuntimeValidationRequest(packet) {
  const errors = [];
  if (!isObject(packet)) return ["runtime-validation-request-not-object"];
  if (packet.schema_version !== RUNTIME_VALIDATION_HANDOFF_SCHEMA_VERSION) errors.push("runtime-validation-request-schema-version-invalid");
  if (packet.packet_type !== REQUEST_TYPE) errors.push("runtime-validation-request-type-invalid");
  for (const field of ["request_id", "audit_id", "finding_id"]) {
    if (!nonEmptyString(packet[field])) errors.push(`runtime-validation-request-${field.replaceAll("_", "-")}-missing`);
  }
  if (!validDigest(packet.scope_digest) || !validDigest(packet.finding_object_digest)) {
    errors.push("runtime-validation-request-identity-digest-invalid");
  }
  const assessment = packet.static_assessment;
  if (!isObject(assessment)
    || !STATIC_STATES.has(assessment.state)
    || !nonEmptyString(assessment.decision_rationale)
    || !validArtifact(assessment.adjudication_artifact)
    || !nonEmptyString(assessment.adjudication_artifact.json_pointer)
    || !assessment.adjudication_artifact.json_pointer.startsWith("/")) {
    errors.push("runtime-validation-request-static-assessment-invalid");
  }
  const source = packet.source_binding;
  if (!isObject(source)
    || !nonEmptyString(source.repository_id)
    || !nonEmptyString(source.commit)
    || !validArtifact(source.finding_artifact)
    || !isObject(source.primary_location)
    || !nonEmptyString(source.primary_location.file)
    || !Number.isInteger(source.primary_location.line_start)
    || !validDigest(source.primary_location.source_digest)) {
    errors.push("runtime-validation-request-source-binding-invalid");
  }
  errors.push(...validateAttackSurface(packet.attack_surface).map(error => `request:${error}`));
  const claim = packet.claim;
  if (!isObject(claim)
    || !nonEmptyString(claim.vulnerability_type_id)
    || !nonEmptyString(claim.summary)
    || !nonEmptyString(claim.expected_security_effect)
    || !validIndexes(claim.source_fact_indexes, { required: true })
    || !validIndexes(claim.sink_or_config_fact_indexes, { required: true })) {
    errors.push("runtime-validation-request-claim-invalid");
  }
  if (!uniqueStrings(packet.proof_gaps, { required: true })) errors.push("runtime-validation-request-proof-gaps-invalid");
  const policy = packet.validation_policy;
  if (!isObject(policy)
    || policy.target_class !== "ISOLATED_TEST_ENVIRONMENT"
    || !uniqueStrings(policy.allowed_methods, { required: true })
    || policy.allowed_methods.some(method => !METHOD_KINDS.has(method))
    || !uniqueStrings(policy.forbidden_actions, { required: true })
    || REQUIRED_FORBIDDEN_ACTIONS.some(action => !policy.forbidden_actions.includes(action))
    || !uniqueStrings(policy.safety_constraints, { required: true })
    || !NETWORK_POLICIES.has(policy.network_access)
    || !CREDENTIAL_POLICIES.has(policy.credentials)) {
    errors.push("runtime-validation-request-policy-invalid");
  }
  if (!isObject(packet.provenance)
    || packet.provenance.producer !== "opencode-multi-agents-static-audit"
    || !nonEmptyString(packet.provenance.exported_by_session_id)) {
    errors.push("runtime-validation-request-provenance-invalid");
  }
  if (packet.packet_digest !== runtimeValidationPacketDigest(packet)) errors.push("runtime-validation-request-digest-invalid");
  return [...new Set(errors)];
}

export function validateExternalRuntimeValidationResult(packet, request) {
  const errors = [];
  const requestErrors = validateExternalRuntimeValidationRequest(request);
  if (requestErrors.length > 0) return requestErrors.map(error => `request:${error}`);
  if (!isObject(packet)) return ["runtime-validation-result-not-object"];
  if (packet.schema_version !== RUNTIME_VALIDATION_HANDOFF_SCHEMA_VERSION) errors.push("runtime-validation-result-schema-version-invalid");
  if (packet.packet_type !== RESULT_TYPE) errors.push("runtime-validation-result-type-invalid");
  for (const field of ["request_id", "audit_id", "finding_id"]) {
    if (packet[field] !== request[field]) errors.push(`runtime-validation-result-${field.replaceAll("_", "-")}-mismatch`);
  }
  for (const field of ["scope_digest", "finding_object_digest"]) {
    if (packet[field] !== request[field]) errors.push(`runtime-validation-result-${field.replaceAll("_", "-")}-mismatch`);
  }
  if (packet.request_packet_digest !== request.packet_digest) errors.push("runtime-validation-result-request-digest-mismatch");
  if (!isObject(packet.validator)
    || !nonEmptyString(packet.validator.project)
    || !nonEmptyString(packet.validator.version)
    || !nonEmptyString(packet.validator.session_id)) {
    errors.push("runtime-validation-result-validator-invalid");
  }
  if (!RESULT_OUTCOMES.has(packet.outcome)) errors.push("runtime-validation-result-outcome-invalid");
  if (!Array.isArray(packet.methods)
    || packet.methods.some(method => !isObject(method)
      || !nonEmptyString(method.method_id)
      || !METHOD_KINDS.has(method.kind)
      || !nonEmptyString(method.description)
      || !nonEmptyString(method.environment))) {
    errors.push("runtime-validation-result-methods-invalid");
  }
  if (!Array.isArray(packet.evidence_artifacts)
    || packet.evidence_artifacts.some(artifact => !validArtifact(artifact)
      || !nonEmptyString(artifact.artifact_id)
      || !nonEmptyString(artifact.kind)
      || !nonEmptyString(artifact.media_type)
      || artifact.sanitized !== true)) {
    errors.push("runtime-validation-result-evidence-artifacts-invalid");
  }
  const artifactIds = new Set((packet.evidence_artifacts ?? []).map(artifact => artifact.artifact_id));
  if (artifactIds.size !== (packet.evidence_artifacts ?? []).length) errors.push("runtime-validation-result-evidence-artifact-id-duplicate");
  if (!Array.isArray(packet.observations)
    || packet.observations.some(observation => !isObject(observation)
      || !nonEmptyString(observation.observation_id)
      || !nonEmptyString(observation.claim)
      || !OBSERVATION_OUTCOMES.has(observation.outcome)
      || !uniqueStrings(observation.evidence_artifact_ids)
      || observation.evidence_artifact_ids.some(id => !artifactIds.has(id)))) {
    errors.push("runtime-validation-result-observations-invalid");
  }
  if (!uniqueStrings(packet.counterevidence) || !uniqueStrings(packet.residual_gaps)) {
    errors.push("runtime-validation-result-gaps-or-counterevidence-invalid");
  }
  const safety = packet.safety_attestation;
  if (!isObject(safety)
    || safety.isolated_test_environment !== true
    || safety.production_targets_contacted !== false
    || safety.third_party_targets_contacted !== false
    || safety.real_credentials_used !== false
    || safety.destructive_actions_performed !== false
    || !uniqueStrings(safety.notes)) {
    errors.push("runtime-validation-result-safety-attestation-invalid");
  }
  if (packet.outcome === "SUPPORTED_RUNTIME"
    && ((packet.methods?.length ?? 0) === 0
      || (packet.evidence_artifacts?.length ?? 0) === 0
      || !(packet.observations ?? []).some(observation => observation.outcome === "CONFIRMS"))) {
    errors.push("runtime-validation-result-runtime-support-missing");
  }
  if (packet.outcome === "REJECTED"
    && !((packet.observations ?? []).some(observation => observation.outcome === "CONTRADICTS")
      || (packet.counterevidence?.length ?? 0) > 0)) {
    errors.push("runtime-validation-result-rejection-evidence-missing");
  }
  if (["INCONCLUSIVE", "NOT_RUN"].includes(packet.outcome) && (packet.residual_gaps?.length ?? 0) === 0) {
    errors.push("runtime-validation-result-residual-gaps-missing");
  }
  if (packet.outcome === "NOT_RUN" && (packet.methods?.length ?? 0) !== 0) {
    errors.push("runtime-validation-result-not-run-has-methods");
  }
  if (packet.packet_digest !== runtimeValidationPacketDigest(packet)) errors.push("runtime-validation-result-digest-invalid");
  return [...new Set(errors)];
}
