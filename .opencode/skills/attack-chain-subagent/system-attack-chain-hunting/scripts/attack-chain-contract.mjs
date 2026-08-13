import { createHash } from "node:crypto";

export const ATTACK_CHAIN_SCHEMA_VERSION = 2;
export const CHAIN_STATES = new Set(["CANDIDATE", "CONDITIONAL", "SUPPORTED_STATIC", "SUPPORTED_RUNTIME", "CONTRADICTED"]);
const STEP_STATES = new Set(["SUPPORTED_STATIC", "SUPPORTED_RUNTIME", "DEPLOYMENT_UNKNOWN", "UNRESOLVED", "CONTRADICTED"]);
const TRANSITION_STATES = new Set(["PROVEN", "UNRESOLVED", "CONTRADICTED"]);

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function validDigest(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function exactSet(value, expected) {
  return Array.isArray(value) && value.length === expected.length
    && new Set(value).size === value.length && expected.every(item => value.includes(item));
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
}

export function attackChainManifestDigest(value) {
  const copy = structuredClone(value);
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(canonicalize(copy))).digest("hex");
}

function admittedFindingIds(adjudication, routing = null, errors = []) {
  if (!isObject(adjudication) || !validDigest(adjudication.manifest_digest) || !Array.isArray(adjudication.decisions)) return null;
  const preliminary = new Set(adjudication.decisions
    .filter(decision => ["SUPPORTED_STATIC", "SUPPORTED_RUNTIME"].includes(decision?.state))
    .map(decision => decision.finding_id)
    .filter(nonEmptyString));
  if (!routing) return preliminary;
  if (!isObject(routing) || routing.artifact_type !== "finding-validation-routing-manifest"
    || routing.audit_id !== adjudication.audit_id || routing.scope_digest !== adjudication.scope_digest
    || routing.complete !== true || !validDigest(routing.artifact_digest) || !Array.isArray(routing.findings)) {
    errors.push("validation-routing-invalid");
    return new Set();
  }
  const routed = new Set(routing.findings.map(item => item?.finding_id).filter(nonEmptyString));
  if (routed.size !== preliminary.size || [...preliminary].some(id => !routed.has(id))) errors.push("validation-routing-accounting-invalid");
  return new Set(routing.findings.filter(item => item?.final_verdict === "TRUE_POSITIVE").map(item => item.finding_id));
}

function validateStep(step, admittedFindings, errors, chainId) {
  if (!isObject(step)) {
    errors.push(`chain:${chainId}:step-not-object`);
    return null;
  }
  if (!nonEmptyString(step.step_id) || !nonEmptyString(step.claim) || !STEP_STATES.has(step.evidence_state)
    || !Array.isArray(step.evidence_refs) || !Array.isArray(step.blocking_gap_ids)) {
    errors.push(`chain:${chainId}:step-invalid`);
    return null;
  }
  if (["SUPPORTED_STATIC", "SUPPORTED_RUNTIME"].includes(step.evidence_state)) {
    if (step.evidence_refs.length === 0 || step.evidence_refs.some(id => !admittedFindings.has(id))) {
      errors.push(`chain:${chainId}:step-evidence-not-adjudicated`);
    }
    if (step.blocking_gap_ids.length > 0) errors.push(`chain:${chainId}:supported-step-has-blocking-gap`);
  }
  if (["DEPLOYMENT_UNKNOWN", "UNRESOLVED", "CONTRADICTED"].includes(step.evidence_state)
    && step.blocking_gap_ids.length === 0) {
    errors.push(`chain:${chainId}:unresolved-step-gap-missing`);
  }
  return step;
}

function validateChain(chain, admittedFindings, gapMap, errors) {
  if (!isObject(chain) || !nonEmptyString(chain.chain_id) || !CHAIN_STATES.has(chain.assessment_state)
    || !Array.isArray(chain.steps) || chain.steps.length === 0 || !Array.isArray(chain.transitions)) {
    errors.push("chain-invalid");
    return;
  }
  const steps = chain.steps.map(step => validateStep(step, admittedFindings, errors, chain.chain_id)).filter(Boolean);
  const stepIds = steps.map(step => step.step_id);
  if (new Set(stepIds).size !== stepIds.length) errors.push(`chain:${chain.chain_id}:step-id-duplicate`);
  const unresolved = steps.filter(step => ["DEPLOYMENT_UNKNOWN", "UNRESOLVED"].includes(step.evidence_state));
  const contradicted = steps.filter(step => step.evidence_state === "CONTRADICTED");
  for (const transition of chain.transitions) {
    if (!isObject(transition) || !nonEmptyString(transition.transition_id) || !TRANSITION_STATES.has(transition.status)
      || !Array.isArray(transition.requires) || transition.requires.length === 0
      || !transition.requires.every(id => stepIds.includes(id))
      || !Array.isArray(transition.produces) || transition.produces.length === 0
      || transition.produces.some(value => !nonEmptyString(value))) {
      errors.push(`chain:${chain.chain_id}:transition-invalid`);
      continue;
    }
    if (transition.status === "PROVEN" && (!Array.isArray(transition.evidence_refs)
      || transition.evidence_refs.length === 0 || transition.evidence_refs.some(id => !admittedFindings.has(id)))) {
      errors.push(`chain:${chain.chain_id}:transition-evidence-not-adjudicated`);
    }
    if (["UNRESOLVED", "CONTRADICTED"].includes(transition.status)
      && (!Array.isArray(transition.blocking_gap_ids) || transition.blocking_gap_ids.length === 0)) {
      errors.push(`chain:${chain.chain_id}:unresolved-transition-gap-missing`);
    }
    for (const gapId of transition.blocking_gap_ids ?? []) {
      if (!gapMap.get(gapId)?.chain_ids?.includes(chain.chain_id)) errors.push(`chain:${chain.chain_id}:gap-not-bidirectional:${gapId}`);
    }
    if (transition.status === "UNRESOLVED") unresolved.push({ step_id: transition.requires[0], blocking_gap_ids: transition.blocking_gap_ids ?? [] });
    if (transition.status === "CONTRADICTED") contradicted.push({ step_id: transition.requires[0], blocking_gap_ids: transition.blocking_gap_ids ?? [] });
  }
  const expectedState = contradicted.length > 0
    ? "CONTRADICTED"
    : unresolved.length > 0
      ? "CONDITIONAL"
      : steps.some(step => step.evidence_state === "SUPPORTED_RUNTIME")
        ? "SUPPORTED_RUNTIME"
        : "SUPPORTED_STATIC";
  if (chain.assessment_state !== expectedState) errors.push(`chain:${chain.chain_id}:assessment-state-mismatch`);
  const firstBlocking = [...contradicted, ...unresolved][0]?.step_id ?? null;
  if (chain.first_blocking_step_id !== firstBlocking) errors.push(`chain:${chain.chain_id}:first-blocking-step-mismatch`);
  for (const step of steps) {
    for (const gapId of step.blocking_gap_ids) {
      if (!gapMap.get(gapId)?.chain_ids?.includes(chain.chain_id)) errors.push(`chain:${chain.chain_id}:gap-not-bidirectional:${gapId}`);
    }
  }
}

export function validateAttackChainManifest(manifest, adjudication, routing = null) {
  const errors = [];
  const admittedFindings = admittedFindingIds(adjudication, routing, errors);
  if (!admittedFindings) return ["adjudication-manifest-invalid"];
  if (!isObject(manifest)) return ["attack-chain-manifest-not-object"];
  if (manifest.schema_version !== ATTACK_CHAIN_SCHEMA_VERSION) errors.push("attack-chain-schema-version-invalid");
  if (!nonEmptyString(manifest.audit_id) || !validDigest(manifest.scope_digest)) errors.push("attack-chain-audit-or-scope-invalid");
  if (manifest.adjudication_manifest_digest !== adjudication.manifest_digest) errors.push("attack-chain-adjudication-digest-mismatch");
  if (routing && manifest.validation_routing_digest !== routing.artifact_digest) errors.push("attack-chain-validation-routing-digest-mismatch");
  if (!Array.isArray(manifest.chains) || !isObject(manifest.chain_accounting) || !Array.isArray(manifest.gaps)) {
    errors.push("attack-chain-collections-missing");
    return errors;
  }
  const gapMap = new Map(manifest.gaps.filter(isObject).map(gap => [gap.gap_id, gap]));
  const ids = manifest.chains.map(chain => chain?.chain_id).filter(nonEmptyString);
  if (ids.length !== manifest.chains.length || new Set(ids).size !== ids.length) errors.push("attack-chain-id-invalid-or-duplicate");
  for (const chain of manifest.chains) validateChain(chain, admittedFindings, gapMap, errors);
  const accepted = manifest.chains.filter(chain => ["CONDITIONAL", "SUPPORTED_STATIC", "SUPPORTED_RUNTIME"].includes(chain.assessment_state)).map(chain => chain.chain_id);
  const rejected = manifest.chains.filter(chain => chain.assessment_state === "CONTRADICTED").map(chain => chain.chain_id);
  if (!exactSet(manifest.chain_accounting.raw_chain_ids, ids)) errors.push("attack-chain-raw-conservation-invalid");
  if (!exactSet(manifest.chain_accounting.accepted_chain_ids, accepted)) errors.push("attack-chain-accepted-conservation-invalid");
  if (!exactSet(manifest.chain_accounting.rejected_chain_ids, rejected)) errors.push("attack-chain-rejected-conservation-invalid");
  if (manifest.manifest_digest !== attackChainManifestDigest(manifest)) errors.push("attack-chain-manifest-digest-invalid");
  return [...new Set(errors)];
}
