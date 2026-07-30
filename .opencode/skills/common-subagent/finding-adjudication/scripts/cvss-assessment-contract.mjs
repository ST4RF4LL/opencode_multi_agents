import { createHash } from "node:crypto";
import { scoreCvssV31 } from "../../finding-evidence-contract/scripts/cvss-v31.mjs";

const SUPPORTED_STATES = new Set(["SUPPORTED_STATIC", "SUPPORTED_RUNTIME"]);

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function uniqueNonEmptyStrings(value) {
  return Array.isArray(value) && value.length > 0 && value.every(nonEmptyString) && new Set(value).size === value.length;
}

function validDigest(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
}

export function cvssAssessmentManifestDigest(value) {
  const copy = structuredClone(value);
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(canonicalize(copy))).digest("hex");
}

export function validateCvssAssessmentClaims(claims, adjudication) {
  const errors = [];
  if (!isObject(claims)) return ["cvss-claims-not-object"];
  if (claims.schema_version !== 1) errors.push("cvss-claims-schema-version-invalid");
  if (claims.audit_id !== adjudication.audit_id || claims.scope_digest !== adjudication.scope_digest) errors.push("cvss-claims-audit-or-scope-mismatch");
  if (claims.adjudication_manifest_digest !== adjudication.manifest_digest) errors.push("cvss-claims-adjudication-digest-mismatch");
  if (!Array.isArray(claims.assessments)) return [...errors, "cvss-claims-assessments-missing"];
  const supported = new Set(adjudication.decisions.filter(item => SUPPORTED_STATES.has(item.state)).map(item => item.finding_id));
  const seen = new Set();
  for (const assessment of claims.assessments) {
    if (!isObject(assessment) || !nonEmptyString(assessment.finding_id) || seen.has(assessment.finding_id)) {
      errors.push("cvss-claim-id-invalid-or-duplicate");
      continue;
    }
    seen.add(assessment.finding_id);
    if (!supported.has(assessment.finding_id)) errors.push(`cvss-claim:${assessment.finding_id}:finding-not-supported`);
    if (!nonEmptyString(assessment.vector) || !nonEmptyString(assessment.rationale)
      || !uniqueNonEmptyStrings(assessment.assumptions) || !uniqueNonEmptyStrings(assessment.evidence_refs)) {
      errors.push(`cvss-claim:${assessment.finding_id}:fields-invalid`);
    }
    try {
      scoreCvssV31(assessment.vector);
    } catch (error) {
      errors.push(`cvss-claim:${assessment.finding_id}:vector-invalid`);
    }
    if (Object.hasOwn(assessment, "base_score") || Object.hasOwn(assessment, "severity")) {
      errors.push(`cvss-claim:${assessment.finding_id}:manual-score-forbidden`);
    }
  }
  for (const findingId of supported) if (!seen.has(findingId)) errors.push(`cvss-claim:${findingId}:missing`);
  return [...new Set(errors)];
}

export function buildCvssAssessmentManifest(claims, adjudication) {
  const errors = validateCvssAssessmentClaims(claims, adjudication);
  if (errors.length > 0) throw new Error(`CVSS assessment claims are invalid:\n- ${errors.join("\n- ")}`);
  const manifest = {
    schema_version: 1,
    audit_id: adjudication.audit_id,
    scope_digest: adjudication.scope_digest,
    adjudication_manifest_digest: adjudication.manifest_digest,
    assessments: claims.assessments.map(assessment => ({
      finding_id: assessment.finding_id,
      ...scoreCvssV31(assessment.vector),
      rationale: assessment.rationale,
      assumptions: assessment.assumptions,
      evidence_refs: assessment.evidence_refs,
    })).sort((left, right) => left.finding_id.localeCompare(right.finding_id)),
  };
  manifest.manifest_digest = cvssAssessmentManifestDigest(manifest);
  return manifest;
}

export function validateCvssAssessmentManifest(manifest, adjudication) {
  const errors = [];
  if (!isObject(manifest)) return ["cvss-assessment-manifest-not-object"];
  if (manifest.schema_version !== 1) errors.push("cvss-assessment-schema-version-invalid");
  if (manifest.audit_id !== adjudication.audit_id || manifest.scope_digest !== adjudication.scope_digest) errors.push("cvss-assessment-audit-or-scope-mismatch");
  if (manifest.adjudication_manifest_digest !== adjudication.manifest_digest) errors.push("cvss-assessment-adjudication-digest-mismatch");
  if (!Array.isArray(manifest.assessments)) return [...errors, "cvss-assessment-rows-missing"];
  const supported = new Set(adjudication.decisions.filter(item => SUPPORTED_STATES.has(item.state)).map(item => item.finding_id));
  const seen = new Set();
  for (const assessment of manifest.assessments) {
    if (!isObject(assessment) || !nonEmptyString(assessment.finding_id) || seen.has(assessment.finding_id)) {
      errors.push("cvss-assessment-id-invalid-or-duplicate");
      continue;
    }
    seen.add(assessment.finding_id);
    if (!supported.has(assessment.finding_id)) errors.push(`cvss-assessment:${assessment.finding_id}:finding-not-supported`);
    if (!nonEmptyString(assessment.rationale) || !uniqueNonEmptyStrings(assessment.assumptions)
      || !uniqueNonEmptyStrings(assessment.evidence_refs)) errors.push(`cvss-assessment:${assessment.finding_id}:fields-invalid`);
    try {
      const derived = scoreCvssV31(assessment.vector);
      if (assessment.base_score !== derived.base_score || assessment.severity !== derived.severity || assessment.vector !== derived.vector) {
        errors.push(`cvss-assessment:${assessment.finding_id}:derived-score-mismatch`);
      }
    } catch (error) {
      errors.push(`cvss-assessment:${assessment.finding_id}:vector-invalid`);
    }
  }
  for (const findingId of supported) if (!seen.has(findingId)) errors.push(`cvss-assessment:${findingId}:missing`);
  if (!validDigest(manifest.manifest_digest) || manifest.manifest_digest !== cvssAssessmentManifestDigest(manifest)) {
    errors.push("cvss-assessment-manifest-digest-invalid");
  }
  return [...new Set(errors)];
}
