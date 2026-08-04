import { createHash } from "node:crypto";
import { findingObjectDigest, validateFinding } from "../../finding-evidence-contract/scripts/finding-contract.mjs";

export const ADJUDICATION_SCHEMA_VERSION = 1;
export const ADJUDICATION_STATES = new Set([
  "SUPPORTED_STATIC",
  "SUPPORTED_RUNTIME",
  "REJECTED",
  "INCONCLUSIVE",
  "RECLASSIFIED",
]);

const TERMINAL_GUARD_STATES = new Set(["PRESENT", "ABSENT", "NOT_APPLICABLE"]);
const ATTACK_SURFACE_REVIEW_DISPOSITIONS = new Set(["ACCEPTED", "LIMITED", "CONTRADICTED", "UNRESOLVED"]);
const ATTACK_SURFACE_REVIEW_FIELDS = [
  "in_scope",
  "exposure",
  "vector",
  "auth_scope",
  "preconditions",
  "identities",
  "boundary_crossing",
  "impact",
  "target_reach",
  "controls",
  "counterevidence",
  "blindspots",
  "confidence",
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

function uniqueNonEmptyStrings(value) {
  return Array.isArray(value) && value.length > 0
    && value.every(nonEmptyString) && new Set(value).size === value.length;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
}

export function adjudicationObjectDigest(value) {
  return createHash("sha256").update(JSON.stringify(canonicalize(value))).digest("hex");
}

export function candidateManifestDigest(value) {
  const copy = structuredClone(value);
  delete copy.manifest_digest;
  return adjudicationObjectDigest(copy);
}

export function validateCandidateManifest(manifest) {
  const errors = [];
  if (!isObject(manifest)) return ["candidate-manifest-not-object"];
  if (manifest.schema_version !== ADJUDICATION_SCHEMA_VERSION) errors.push("candidate-manifest-schema-version-invalid");
  if (!nonEmptyString(manifest.audit_id)) errors.push("candidate-manifest-audit-id-missing");
  if (!validDigest(manifest.scope_digest)) errors.push("candidate-manifest-scope-digest-invalid");
  if (!validDigest(manifest.plan_digest)) errors.push("candidate-manifest-plan-digest-invalid");
  if (!validDigest(manifest.structural_digest)) errors.push("candidate-manifest-structural-digest-invalid");
  if (!Array.isArray(manifest.candidates)) {
    errors.push("candidate-manifest-candidates-missing");
    return errors;
  }
  const ids = new Set();
  for (const candidate of manifest.candidates) {
    if (!isObject(candidate)) {
      errors.push("candidate-not-object");
      continue;
    }
    if (!nonEmptyString(candidate.finding_id)) errors.push("candidate-finding-id-missing");
    else if (ids.has(candidate.finding_id)) errors.push("candidate-finding-id-duplicate");
    else ids.add(candidate.finding_id);
    if (!nonEmptyString(candidate.primary_check_id)) errors.push("candidate-primary-check-missing");
    if (!validDigest(candidate.finding_object_digest)) errors.push("candidate-finding-object-digest-invalid");
    const findingErrors = validateFinding(candidate.finding, {
      expectedFindingId: candidate.finding_id,
      auditId: manifest.audit_id,
      scopeDigest: manifest.scope_digest,
    });
    errors.push(...findingErrors.map(error => `candidate:${candidate.finding_id ?? "unknown"}:${error}`));
    if (candidate.finding && findingObjectDigest(candidate.finding) !== candidate.finding_object_digest) {
      errors.push(`candidate:${candidate.finding_id ?? "unknown"}:finding-object-digest-mismatch`);
    }
    if (candidate.finding?.state !== "CANDIDATE") errors.push(`candidate:${candidate.finding_id ?? "unknown"}:finding-state-must-be-candidate`);
  }
  if (manifest.manifest_digest !== candidateManifestDigest(manifest)) errors.push("candidate-manifest-digest-invalid");
  return [...new Set(errors)];
}

function indexesOfKind(candidate, indexes, kind) {
  const facts = candidate.finding?.evidence?.facts ?? [];
  return indexes.every(index => Number.isInteger(index) && index >= 0 && index < facts.length && facts[index].kind === kind);
}

function validateEvidenceIndexes(decision, candidate, errors) {
  const proof = decision.semantic_proof;
  if (!isObject(proof)) {
    errors.push("semantic-proof-missing");
    return;
  }
  if (!Array.isArray(proof.source_fact_indexes) || proof.source_fact_indexes.length === 0
    || !indexesOfKind(candidate, proof.source_fact_indexes, "source")) {
    errors.push("semantic-proof-source-facts-invalid");
  }
  const semanticFacts = proof.sink_or_config_fact_indexes;
  const facts = candidate.finding?.evidence?.facts ?? [];
  if (!Array.isArray(semanticFacts) || semanticFacts.length === 0
    || !semanticFacts.every(index => Number.isInteger(index) && index >= 0 && index < facts.length
      && ["sink", "config"].includes(facts[index].kind))) {
    errors.push("semantic-proof-sink-or-config-facts-invalid");
  }
  if (!isObject(proof.framework)
    || !nonEmptyString(proof.framework.component)
    || !nonEmptyString(proof.framework.version_or_commit)
    || !nonEmptyString(proof.framework.api_or_configuration)
    || !uniqueNonEmptyStrings(proof.framework.evidence)) {
    errors.push("semantic-proof-framework-context-invalid");
  }
  if (!isObject(proof.path)
    || !nonEmptyString(proof.path.state)
    || !uniqueNonEmptyStrings(proof.path.steps)) {
    errors.push("semantic-proof-path-invalid");
  }
  if (!isObject(proof.security_effect)
    || !nonEmptyString(proof.security_effect.state)
    || !nonEmptyString(proof.security_effect.rationale)) {
    errors.push("semantic-proof-security-effect-invalid");
  }
}

function validateGuards(decision, errors) {
  if (!Array.isArray(decision.guards) || decision.guards.length === 0) {
    errors.push("adjudication-guards-missing");
    return [];
  }
  const scopes = new Set();
  for (const guard of decision.guards) {
    if (!isObject(guard) || !["local", "inherited", "global", "deployment"].includes(guard.scope)
      || !nonEmptyString(guard.state) || !nonEmptyString(guard.rationale) || !uniqueNonEmptyStrings(guard.evidence)) {
      errors.push("adjudication-guard-invalid");
      continue;
    }
    scopes.add(guard.scope);
  }
  if (!["local", "inherited", "global", "deployment"].every(scope => scopes.has(scope))) {
    errors.push("adjudication-guard-scope-incomplete");
  }
  return decision.guards;
}

function validateCounterclaim(decision, errors) {
  const counterclaim = decision.counterclaim;
  if (!isObject(counterclaim)
    || !nonEmptyString(counterclaim.claim)
    || !["REFUTED", "SUPPORTED", "UNRESOLVED"].includes(counterclaim.outcome)
    || !uniqueNonEmptyStrings(counterclaim.evidence)) {
    errors.push("counterclaim-invalid");
    return null;
  }
  return counterclaim;
}

export function validateAttackSurfaceReview(review, decisionState = null) {
  const errors = [];
  if (!isObject(review)) return ["attack-surface-review-missing"];
  if (!ATTACK_SURFACE_REVIEW_DISPOSITIONS.has(review.disposition)) errors.push("attack-surface-review-disposition-invalid");
  if (!Array.isArray(review.reviewed_fields)
    || review.reviewed_fields.length !== ATTACK_SURFACE_REVIEW_FIELDS.length
    || new Set(review.reviewed_fields).size !== review.reviewed_fields.length
    || ATTACK_SURFACE_REVIEW_FIELDS.some(field => !review.reviewed_fields.includes(field))) {
    errors.push("attack-surface-review-fields-incomplete");
  }
  if (!nonEmptyString(review.rationale)) errors.push("attack-surface-review-rationale-missing");
  if (!uniqueNonEmptyStrings(review.evidence)) errors.push("attack-surface-review-evidence-invalid");
  if (!Array.isArray(review.limitations) || review.limitations.some(value => !nonEmptyString(value))) {
    errors.push("attack-surface-review-limitations-invalid");
  }
  if (review.disposition === "LIMITED" && Array.isArray(review.limitations) && review.limitations.length === 0) {
    errors.push("attack-surface-review-limited-without-limitations");
  }
  if (["SUPPORTED_STATIC", "SUPPORTED_RUNTIME"].includes(decisionState)
    && !["ACCEPTED", "LIMITED"].includes(review.disposition)) {
    errors.push("supported-decision-attack-surface-not-admitted");
  }
  if (decisionState === "INCONCLUSIVE" && review.disposition !== "UNRESOLVED") {
    errors.push("inconclusive-decision-attack-surface-not-unresolved");
  }
  return [...new Set(errors)];
}

function validateDecision(decision, candidate) {
  const errors = [];
  if (!isObject(decision)) return ["decision-not-object"];
  if (!nonEmptyString(decision.finding_id) || decision.finding_id !== candidate.finding_id) errors.push("decision-finding-id-mismatch");
  if (decision.finding_object_digest !== candidate.finding_object_digest) errors.push("decision-finding-object-digest-mismatch");
  if (!ADJUDICATION_STATES.has(decision.state)) errors.push("decision-state-invalid");
  if (!nonEmptyString(decision.decision_rationale)) errors.push("decision-rationale-missing");
  if (!Array.isArray(decision.contradiction_refs)) errors.push("decision-contradiction-refs-missing");
  if (!Array.isArray(decision.blocking_questions)) errors.push("decision-blocking-questions-missing");
  validateEvidenceIndexes(decision, candidate, errors);
  const guards = validateGuards(decision, errors);
  const counterclaim = validateCounterclaim(decision, errors);
  const proof = decision.semantic_proof;
  errors.push(...validateAttackSurfaceReview(decision.attack_surface_review, decision.state));

  if (["SUPPORTED_STATIC", "SUPPORTED_RUNTIME"].includes(decision.state)) {
    if (counterclaim?.outcome !== "REFUTED") errors.push("supported-decision-counterclaim-not-refuted");
    if (proof?.path?.state !== "PROVEN") errors.push("supported-decision-path-not-proven");
    if (proof?.security_effect?.state !== "PROVEN") errors.push("supported-decision-security-effect-not-proven");
    if (guards.some(guard => !TERMINAL_GUARD_STATES.has(guard.state))) errors.push("supported-decision-guard-unknown");
    if (guards.some(guard => guard.effective_for_claim === true)) errors.push("supported-decision-effective-guard-present");
    if (decision.state === "SUPPORTED_RUNTIME" && !uniqueNonEmptyStrings(decision.runtime_evidence)) {
      errors.push("runtime-decision-evidence-missing");
    }
  }
  if (decision.state === "REJECTED") {
    if (counterclaim?.outcome !== "SUPPORTED") errors.push("rejected-decision-counterclaim-not-supported");
    if (!nonEmptyString(decision.rejection_reason)) errors.push("rejected-decision-reason-missing");
  }
  if (decision.state === "INCONCLUSIVE") {
    if (counterclaim?.outcome !== "UNRESOLVED") errors.push("inconclusive-decision-counterclaim-not-unresolved");
    if (!uniqueNonEmptyStrings(decision.blocking_questions)) errors.push("inconclusive-decision-questions-missing");
  }
  if (decision.state === "RECLASSIFIED") {
    const reclassification = decision.reclassification;
    if (!isObject(reclassification)
      || !nonEmptyString(reclassification.vulnerability_type_id)
      || !Array.isArray(reclassification.dimension_claims)
      || reclassification.dimension_claims.length === 0) {
      errors.push("reclassified-decision-target-missing");
    }
  }
  return [...new Set(errors)];
}

export function validateAdjudicationManifest(manifest, candidateManifest) {
  const errors = [];
  const candidateErrors = validateCandidateManifest(candidateManifest);
  if (candidateErrors.length > 0) return candidateErrors.map(error => `input:${error}`);
  if (!isObject(manifest)) return ["adjudication-manifest-not-object"];
  if (manifest.schema_version !== ADJUDICATION_SCHEMA_VERSION) errors.push("adjudication-schema-version-invalid");
  if (manifest.audit_id !== candidateManifest.audit_id) errors.push("adjudication-audit-id-mismatch");
  if (manifest.scope_digest !== candidateManifest.scope_digest) errors.push("adjudication-scope-digest-mismatch");
  if (manifest.input_manifest_digest !== candidateManifest.manifest_digest) errors.push("adjudication-input-manifest-digest-mismatch");
  if (!nonEmptyString(manifest.adjudicator_session_id)) errors.push("adjudicator-session-id-missing");
  if (!Array.isArray(manifest.decisions)) {
    errors.push("adjudication-decisions-missing");
    return errors;
  }
  const candidates = new Map(candidateManifest.candidates.map(candidate => [candidate.finding_id, candidate]));
  const seen = new Set();
  for (const decision of manifest.decisions) {
    const candidate = candidates.get(decision?.finding_id);
    if (!candidate) {
      errors.push(`decision:${decision?.finding_id ?? "unknown"}:candidate-not-in-input`);
      continue;
    }
    if (seen.has(decision.finding_id)) {
      errors.push(`decision:${decision.finding_id}:duplicate`);
      continue;
    }
    seen.add(decision.finding_id);
    errors.push(...validateDecision(decision, candidate).map(error => `decision:${decision.finding_id}:${error}`));
  }
  for (const findingId of candidates.keys()) if (!seen.has(findingId)) errors.push(`decision:${findingId}:missing`);
  if (manifest.manifest_digest !== candidateManifestDigest(manifest)) errors.push("adjudication-manifest-digest-invalid");
  return [...new Set(errors)];
}
