import { createHash } from "node:crypto";

export const STAGE_DELIVERY_SCHEMA_VERSION = 1;

const EXPECTED_STAGE_IDS = [
  "scope",
  "recon",
  "threat",
  "audit",
  "correlation",
  "adjudication",
  "validation",
  "report",
];
const REGISTRY_STATES = new Set(["DRAFT", "DESIGN_LOCKED", "ACTIVE", "RETIRED"]);
const ENFORCEMENT_MODES = new Set(["SHADOW", "ENFORCED"]);
const REQUIREMENTS = new Set(["REQUIRED", "CONDITIONAL", "OPTIONAL"]);
const CARDINALITIES = new Set(["ONE", "ONE_OR_MORE", "ZERO_OR_ONE", "ZERO_OR_MORE"]);
const VALIDATION_LEVELS = new Set(["DETERMINISTIC", "SCHEMA", "ENVELOPE_ONLY", "DECLARED"]);
const VALIDATION_STATUSES = new Set(["PASS", "FAIL", "NOT_RUN", "NOT_APPLICABLE"]);
const SCOPE_STATES = new Set(["UNFROZEN", "FROZEN"]);

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

function exactKeys(value, expected) {
  return isObject(value)
    && Object.keys(value).length === expected.length
    && expected.every(key => Object.hasOwn(value, key));
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
}

function digestWithout(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return createHash("sha256").update(JSON.stringify(canonicalize(copy))).digest("hex");
}

export function stageDeliveryRegistryDigest(registry) {
  return digestWithout(registry, "registry_digest");
}

export function stageDeliveryManifestDigest(manifest) {
  return digestWithout(manifest, "manifest_digest");
}

function validateArtifactTemplate(artifact, prefix, errors, knownStageIds) {
  const keys = [
    "artifact_type",
    "requirement",
    "cardinality",
    "source_stage_ids",
    "producer",
    "path_template",
    "validation_level",
    "contract_ref",
    "validator_ref",
    "condition_id",
  ];
  if (!exactKeys(artifact, keys)) {
    errors.push(`${prefix}:fields-not-exact`);
    return;
  }
  if (!nonEmptyString(artifact.artifact_type)) errors.push(`${prefix}:artifact-type-invalid`);
  if (!REQUIREMENTS.has(artifact.requirement)) errors.push(`${prefix}:requirement-invalid`);
  if (!CARDINALITIES.has(artifact.cardinality)) errors.push(`${prefix}:cardinality-invalid`);
  if (!uniqueStrings(artifact.source_stage_ids)) errors.push(`${prefix}:source-stage-ids-invalid`);
  for (const stageId of artifact.source_stage_ids ?? []) {
    if (!knownStageIds.has(stageId)) errors.push(`${prefix}:source-stage-id-unknown:${stageId}`);
  }
  if (!nonEmptyString(artifact.producer)) errors.push(`${prefix}:producer-invalid`);
  if (!nonEmptyString(artifact.path_template) || !artifact.path_template.startsWith("reports/")) {
    errors.push(`${prefix}:path-template-invalid`);
  }
  if (!VALIDATION_LEVELS.has(artifact.validation_level)) errors.push(`${prefix}:validation-level-invalid`);
  if (!(artifact.contract_ref === null || nonEmptyString(artifact.contract_ref))) errors.push(`${prefix}:contract-ref-invalid`);
  if (!(artifact.validator_ref === null || nonEmptyString(artifact.validator_ref))) errors.push(`${prefix}:validator-ref-invalid`);
  if (artifact.validation_level === "DETERMINISTIC" && !nonEmptyString(artifact.validator_ref)) {
    errors.push(`${prefix}:deterministic-validator-missing`);
  }
  if (artifact.validation_level === "SCHEMA" && !nonEmptyString(artifact.contract_ref)) {
    errors.push(`${prefix}:schema-contract-missing`);
  }
  if (artifact.requirement === "CONDITIONAL") {
    if (!nonEmptyString(artifact.condition_id)) errors.push(`${prefix}:condition-id-missing`);
  } else if (artifact.condition_id !== null) {
    errors.push(`${prefix}:condition-id-unexpected`);
  }
}

function validateValidatorTemplate(validator, prefix, errors, artifactTypes) {
  const keys = ["validator_id", "requirement", "artifact_types", "validator_ref", "pass_condition", "condition_id"];
  if (!exactKeys(validator, keys)) {
    errors.push(`${prefix}:fields-not-exact`);
    return;
  }
  if (!nonEmptyString(validator.validator_id)) errors.push(`${prefix}:validator-id-invalid`);
  if (!REQUIREMENTS.has(validator.requirement)) errors.push(`${prefix}:requirement-invalid`);
  if (!uniqueStrings(validator.artifact_types, { required: true })) errors.push(`${prefix}:artifact-types-invalid`);
  for (const artifactType of validator.artifact_types ?? []) {
    if (!artifactTypes.has(artifactType)) errors.push(`${prefix}:artifact-type-unknown:${artifactType}`);
  }
  if (!nonEmptyString(validator.validator_ref)) errors.push(`${prefix}:validator-ref-invalid`);
  if (!nonEmptyString(validator.pass_condition)) errors.push(`${prefix}:pass-condition-invalid`);
  if (validator.requirement === "CONDITIONAL") {
    if (!nonEmptyString(validator.condition_id)) errors.push(`${prefix}:condition-id-missing`);
  } else if (validator.condition_id !== null) {
    errors.push(`${prefix}:condition-id-unexpected`);
  }
}

export function validateStageDeliveryRegistry(registry, stageAgentRegistry = null) {
  const errors = [];
  const registryKeys = [
    "schema_version",
    "registry_id",
    "purpose",
    "lifecycle",
    "manifest",
    "statuses",
    "stages",
    "feedback_edges",
    "registry_digest",
  ];
  if (!exactKeys(registry, registryKeys)) return ["stage-delivery-registry-fields-not-exact"];
  if (registry.schema_version !== STAGE_DELIVERY_SCHEMA_VERSION) errors.push("stage-delivery-registry-schema-version-invalid");
  if (!nonEmptyString(registry.registry_id)) errors.push("stage-delivery-registry-id-invalid");
  if (!nonEmptyString(registry.purpose)) errors.push("stage-delivery-registry-purpose-invalid");
  if (!exactKeys(registry.lifecycle, ["state", "enforcement", "compatibility"])
    || !REGISTRY_STATES.has(registry.lifecycle?.state)
    || !ENFORCEMENT_MODES.has(registry.lifecycle?.enforcement)
    || !nonEmptyString(registry.lifecycle?.compatibility)) {
    errors.push("stage-delivery-registry-lifecycle-invalid");
  }
  if (!exactKeys(registry.manifest, ["schema_version", "path_template", "schema_ref"])
    || registry.manifest?.schema_version !== STAGE_DELIVERY_SCHEMA_VERSION
    || !nonEmptyString(registry.manifest?.path_template)
    || !registry.manifest.path_template.startsWith("reports/")
    || !nonEmptyString(registry.manifest?.schema_ref)) {
    errors.push("stage-delivery-registry-manifest-invalid");
  }
  if (!uniqueStrings(registry.statuses, { required: true }) || !registry.statuses.includes("COMPLETE")) {
    errors.push("stage-delivery-registry-statuses-invalid");
  }
  if (!Array.isArray(registry.stages) || registry.stages.length !== EXPECTED_STAGE_IDS.length) {
    errors.push("stage-delivery-registry-stages-invalid");
  }
  if (!Array.isArray(registry.feedback_edges)) errors.push("stage-delivery-registry-feedback-edges-invalid");

  const knownStageIds = new Set((registry.stages ?? []).map(stage => stage?.stage_id).filter(nonEmptyString));
  const internalStageIds = stageAgentRegistry
    ? new Set((stageAgentRegistry.stages ?? []).map(stage => stage.stage_id))
    : null;
  const stageAgentContractIds = stageAgentRegistry
    ? new Set((stageAgentRegistry.contracts ?? []).map(contract => contract.contract_id))
    : null;
  const stageMap = new Map();
  const templateIds = new Set();

  for (let index = 0; index < (registry.stages ?? []).length; index += 1) {
    const stage = registry.stages[index];
    const prefix = `stage:${stage?.stage_id ?? index}`;
    const stageKeys = [
      "stage_id",
      "template_id",
      "order",
      "label",
      "objective",
      "internal_stage_ids",
      "stage_agent_contract_ids",
      "predecessor_stage_ids",
      "input_artifacts",
      "output_artifacts",
      "validators",
      "completion_gate",
      "recovery_policy",
      "integration_notes",
    ];
    if (!exactKeys(stage, stageKeys)) {
      errors.push(`${prefix}:fields-not-exact`);
      continue;
    }
    if (stage.stage_id !== EXPECTED_STAGE_IDS[index] || stage.order !== index + 1 || stageMap.has(stage.stage_id)) {
      errors.push(`${prefix}:identity-or-order-invalid`);
    }
    stageMap.set(stage.stage_id, stage);
    if (!nonEmptyString(stage.template_id) || templateIds.has(stage.template_id)) errors.push(`${prefix}:template-id-invalid`);
    templateIds.add(stage.template_id);
    if (!nonEmptyString(stage.label) || !nonEmptyString(stage.objective)) errors.push(`${prefix}:narrative-invalid`);
    if (!uniqueStrings(stage.internal_stage_ids, { required: true })) errors.push(`${prefix}:internal-stage-ids-invalid`);
    if (!uniqueStrings(stage.stage_agent_contract_ids, { required: true })) errors.push(`${prefix}:stage-agent-contract-ids-invalid`);
    for (const stageId of stage.internal_stage_ids ?? []) {
      if (internalStageIds && !internalStageIds.has(stageId)) errors.push(`${prefix}:internal-stage-id-unknown:${stageId}`);
    }
    for (const contractId of stage.stage_agent_contract_ids ?? []) {
      if (stageAgentContractIds && !stageAgentContractIds.has(contractId)) errors.push(`${prefix}:stage-agent-contract-id-unknown:${contractId}`);
    }
    if (!uniqueStrings(stage.predecessor_stage_ids)) errors.push(`${prefix}:predecessor-stage-ids-invalid`);
    for (const predecessor of stage.predecessor_stage_ids ?? []) {
      if (!knownStageIds.has(predecessor) || EXPECTED_STAGE_IDS.indexOf(predecessor) >= index) {
        errors.push(`${prefix}:predecessor-stage-id-invalid:${predecessor}`);
      }
    }
    if (!Array.isArray(stage.input_artifacts) || !Array.isArray(stage.output_artifacts)) {
      errors.push(`${prefix}:artifact-templates-invalid`);
      continue;
    }
    const inputTypes = new Set();
    const outputTypes = new Set();
    for (const [side, artifacts, types] of [
      ["input", stage.input_artifacts, inputTypes],
      ["output", stage.output_artifacts, outputTypes],
    ]) {
      for (let artifactIndex = 0; artifactIndex < artifacts.length; artifactIndex += 1) {
        const artifact = artifacts[artifactIndex];
        validateArtifactTemplate(artifact, `${prefix}:${side}:${artifactIndex}`, errors, knownStageIds);
        if (types.has(artifact?.artifact_type)) errors.push(`${prefix}:${side}:artifact-type-duplicate:${artifact.artifact_type}`);
        types.add(artifact?.artifact_type);
        if (side === "output" && !artifact?.source_stage_ids?.includes(stage.stage_id)) {
          errors.push(`${prefix}:output:source-stage-id-mismatch:${artifact?.artifact_type ?? artifactIndex}`);
        }
      }
    }
    const artifactTypes = new Set([...inputTypes, ...outputTypes]);
    if (!Array.isArray(stage.validators)) errors.push(`${prefix}:validators-invalid`);
    const validatorIds = new Set();
    for (let validatorIndex = 0; validatorIndex < (stage.validators ?? []).length; validatorIndex += 1) {
      const validator = stage.validators[validatorIndex];
      validateValidatorTemplate(validator, `${prefix}:validator:${validatorIndex}`, errors, artifactTypes);
      if (validatorIds.has(validator?.validator_id)) errors.push(`${prefix}:validator-id-duplicate:${validator.validator_id}`);
      validatorIds.add(validator?.validator_id);
    }
    if (!exactKeys(stage.completion_gate, [
      "required_output_types",
      "required_validator_ids",
      "requires_predecessors_complete",
      "requires_zero_gaps",
    ])
      || !uniqueStrings(stage.completion_gate?.required_output_types, { required: true })
      || !uniqueStrings(stage.completion_gate?.required_validator_ids, { required: true })
      || typeof stage.completion_gate?.requires_predecessors_complete !== "boolean"
      || typeof stage.completion_gate?.requires_zero_gaps !== "boolean") {
      errors.push(`${prefix}:completion-gate-invalid`);
    } else {
      const expectedOutputs = stage.output_artifacts.filter(item => item.requirement === "REQUIRED").map(item => item.artifact_type).sort();
      const expectedValidators = stage.validators.filter(item => item.requirement === "REQUIRED").map(item => item.validator_id).sort();
      if (JSON.stringify([...stage.completion_gate.required_output_types].sort()) !== JSON.stringify(expectedOutputs)) {
        errors.push(`${prefix}:completion-required-outputs-mismatch`);
      }
      if (JSON.stringify([...stage.completion_gate.required_validator_ids].sort()) !== JSON.stringify(expectedValidators)) {
        errors.push(`${prefix}:completion-required-validators-mismatch`);
      }
    }
    if (!exactKeys(stage.recovery_policy, ["anchor_artifact_types", "invalidate_on_input_change", "resume_rule"])
      || !uniqueStrings(stage.recovery_policy?.anchor_artifact_types, { required: true })
      || typeof stage.recovery_policy?.invalidate_on_input_change !== "boolean"
      || !nonEmptyString(stage.recovery_policy?.resume_rule)) {
      errors.push(`${prefix}:recovery-policy-invalid`);
    }
    for (const artifactType of stage.recovery_policy?.anchor_artifact_types ?? []) {
      if (!outputTypes.has(artifactType)) errors.push(`${prefix}:recovery-anchor-unknown:${artifactType}`);
    }
    if (!uniqueStrings(stage.integration_notes)) errors.push(`${prefix}:integration-notes-invalid`);
  }

  const feedbackConditions = new Set();
  for (let index = 0; index < (registry.feedback_edges ?? []).length; index += 1) {
    const edge = registry.feedback_edges[index];
    const prefix = `feedback-edge:${index}`;
    if (!exactKeys(edge, ["from_stage_id", "to_stage_id", "condition_id", "allowed_source_statuses", "round_rule", "description"])
      || !knownStageIds.has(edge?.from_stage_id)
      || !knownStageIds.has(edge?.to_stage_id)
      || !nonEmptyString(edge?.condition_id)
      || feedbackConditions.has(edge?.condition_id)
      || !uniqueStrings(edge?.allowed_source_statuses, { required: true })
      || edge.allowed_source_statuses.some(status => !registry.statuses.includes(status))
      || !nonEmptyString(edge?.round_rule)
      || !nonEmptyString(edge?.description)) {
      errors.push(`${prefix}:invalid`);
      continue;
    }
    feedbackConditions.add(edge.condition_id);
    if (EXPECTED_STAGE_IDS.indexOf(edge.from_stage_id) <= EXPECTED_STAGE_IDS.indexOf(edge.to_stage_id)) {
      errors.push(`${prefix}:not-backward`);
    }
  }

  for (const stage of registry.stages ?? []) {
    const allowedSources = new Set([
      ...(stage.predecessor_stage_ids ?? []),
      ...(registry.feedback_edges ?? []).filter(edge => edge.to_stage_id === stage.stage_id).map(edge => edge.from_stage_id),
    ]);
    for (const input of stage.input_artifacts ?? []) {
      for (const sourceStageId of input.source_stage_ids ?? []) {
        if (!allowedSources.has(sourceStageId)) errors.push(`stage:${stage.stage_id}:input-source-not-predecessor:${input.artifact_type}:${sourceStageId}`);
        const sourceStage = stageMap.get(sourceStageId);
        if (sourceStage && !(sourceStage.output_artifacts ?? []).some(output => output.artifact_type === input.artifact_type)) {
          errors.push(`stage:${stage.stage_id}:input-not-produced:${input.artifact_type}:${sourceStageId}`);
        }
      }
    }
  }

  if (!validDigest(registry.registry_digest) || registry.registry_digest !== stageDeliveryRegistryDigest(registry)) {
    errors.push("stage-delivery-registry-digest-invalid");
  }
  return [...new Set(errors)];
}

function validateScopeBinding(binding, errors) {
  if (!exactKeys(binding, ["state", "scope_digest"]) || !SCOPE_STATES.has(binding?.state)) {
    errors.push("stage-delivery-scope-binding-invalid");
    return;
  }
  if ((binding.state === "FROZEN" && !validDigest(binding.scope_digest))
    || (binding.state === "UNFROZEN" && binding.scope_digest !== null)) {
    errors.push("stage-delivery-scope-binding-invalid");
  }
}

function validateArtifactBindings(bindings, templates, manifest, side, errors) {
  if (!Array.isArray(bindings)) {
    errors.push(`stage-delivery-${side}-artifacts-invalid`);
    return new Map();
  }
  const identities = new Set();
  const counts = new Map();
  const templateMap = new Map(templates.map(template => [template.artifact_type, template]));
  for (const binding of bindings) {
    if (!exactKeys(binding, ["artifact_type", "path", "sha256", "media_type", "json_pointer"])
      || !nonEmptyString(binding.artifact_type)
      || !nonEmptyString(binding.path)
      || !binding.path.startsWith("reports/")
      || !validDigest(binding.sha256)
      || !nonEmptyString(binding.media_type)
      || !(binding.json_pointer === null || (nonEmptyString(binding.json_pointer) && binding.json_pointer.startsWith("/")))) {
      errors.push(`stage-delivery-${side}-artifact-binding-invalid`);
      continue;
    }
    const template = templateMap.get(binding.artifact_type);
    if (!template) {
      errors.push(`stage-delivery-${side}-artifact-type-undeclared:${binding.artifact_type}`);
      continue;
    }
    const identity = `${binding.artifact_type}|${binding.path}|${binding.json_pointer ?? ""}`;
    if (identities.has(identity)) errors.push(`stage-delivery-${side}-artifact-binding-duplicate`);
    identities.add(identity);
    counts.set(binding.artifact_type, (counts.get(binding.artifact_type) ?? 0) + 1);
    const pathPattern = template.path_template
      .replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&")
      .replaceAll("\\{audit_id\\}", manifest.audit_id.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .replaceAll("\\{round\\}", String(manifest.round))
      .replaceAll(/\\\{[a-z0-9_]+\\\}/gi, "[^/]+")
      .replaceAll("\\*", "[^/]+");
    if (!new RegExp(`^${pathPattern}$`).test(binding.path)) errors.push(`stage-delivery-${side}-artifact-path-mismatch:${binding.artifact_type}`);
  }
  for (const template of templates) {
    const count = counts.get(template.artifact_type) ?? 0;
    const required = template.requirement === "REQUIRED"
      || (template.requirement === "CONDITIONAL" && manifest.activated_conditions.includes(template.condition_id));
    if (required && count === 0) errors.push(`stage-delivery-${side}-required-artifact-missing:${template.artifact_type}`);
    if (["ONE", "ZERO_OR_ONE"].includes(template.cardinality) && count > 1) errors.push(`stage-delivery-${side}-artifact-cardinality-invalid:${template.artifact_type}`);
    if (required && template.cardinality === "ONE" && count !== 1) errors.push(`stage-delivery-${side}-artifact-cardinality-invalid:${template.artifact_type}`);
    if (required && template.cardinality === "ONE_OR_MORE" && count < 1) errors.push(`stage-delivery-${side}-artifact-cardinality-invalid:${template.artifact_type}`);
  }
  return counts;
}

function validateGaps(gaps, errors) {
  if (!Array.isArray(gaps)) {
    errors.push("stage-delivery-gaps-invalid");
    return;
  }
  const ids = new Set();
  for (const gap of gaps) {
    if (!exactKeys(gap, ["gap_id", "category", "description", "blocking", "evidence_refs"])
      || !nonEmptyString(gap.gap_id)
      || ids.has(gap.gap_id)
      || !nonEmptyString(gap.category)
      || !nonEmptyString(gap.description)
      || typeof gap.blocking !== "boolean"
      || !uniqueStrings(gap.evidence_refs)) {
      errors.push("stage-delivery-gap-invalid");
    } else {
      ids.add(gap.gap_id);
    }
  }
}

export function validateStageDeliveryManifest(manifest, registry, context = {}) {
  const errors = [];
  const registryErrors = validateStageDeliveryRegistry(registry, context.stageAgentRegistry ?? null);
  if (registryErrors.length > 0) return registryErrors.map(error => `registry:${error}`);
  const fields = [
    "schema_version",
    "registry_id",
    "registry_digest",
    "template_id",
    "stage_id",
    "stage_order",
    "audit_id",
    "round",
    "status",
    "scope_binding",
    "activated_conditions",
    "predecessor_manifests",
    "input_artifacts",
    "output_artifacts",
    "validation_results",
    "gaps",
    "producer",
    "started_at",
    "completed_at",
    "completion",
    "manifest_digest",
  ];
  if (!exactKeys(manifest, fields)) return ["stage-delivery-manifest-fields-not-exact"];
  const stage = registry.stages.find(item => item.stage_id === manifest.stage_id);
  if (!stage) return ["stage-delivery-stage-id-unknown"];
  if (manifest.schema_version !== STAGE_DELIVERY_SCHEMA_VERSION) errors.push("stage-delivery-schema-version-invalid");
  if (manifest.registry_id !== registry.registry_id || manifest.registry_digest !== registry.registry_digest) {
    errors.push("stage-delivery-registry-binding-invalid");
  }
  if (manifest.template_id !== stage.template_id || manifest.stage_order !== stage.order) errors.push("stage-delivery-template-binding-invalid");
  if (!nonEmptyString(manifest.audit_id)) errors.push("stage-delivery-audit-id-invalid");
  if (!Number.isInteger(manifest.round) || manifest.round < 1) errors.push("stage-delivery-round-invalid");
  if (!registry.statuses.includes(manifest.status)) errors.push("stage-delivery-status-invalid");
  validateScopeBinding(manifest.scope_binding, errors);
  if (!uniqueStrings(manifest.activated_conditions)) errors.push("stage-delivery-activated-conditions-invalid");

  const knownConditions = new Set([
    ...stage.input_artifacts.filter(item => item.condition_id).map(item => item.condition_id),
    ...stage.output_artifacts.filter(item => item.condition_id).map(item => item.condition_id),
    ...stage.validators.filter(item => item.condition_id).map(item => item.condition_id),
    ...registry.feedback_edges.filter(edge => edge.to_stage_id === stage.stage_id).map(edge => edge.condition_id),
  ]);
  for (const condition of manifest.activated_conditions ?? []) {
    if (!knownConditions.has(condition)) errors.push(`stage-delivery-condition-unknown:${condition}`);
  }

  if (!Array.isArray(manifest.predecessor_manifests)) errors.push("stage-delivery-predecessors-invalid");
  const predecessorIds = new Set();
  for (const predecessor of manifest.predecessor_manifests ?? []) {
    if (!exactKeys(predecessor, ["stage_id", "round", "path", "sha256", "manifest_digest", "status"])
      || !nonEmptyString(predecessor.stage_id)
      || predecessorIds.has(predecessor.stage_id)
      || !Number.isInteger(predecessor.round)
      || predecessor.round < 1
      || !nonEmptyString(predecessor.path)
      || !predecessor.path.startsWith("reports/")
      || !validDigest(predecessor.sha256)
      || !validDigest(predecessor.manifest_digest)
      || !registry.statuses.includes(predecessor.status)) {
      errors.push("stage-delivery-predecessor-invalid");
    } else {
      predecessorIds.add(predecessor.stage_id);
    }
  }
  const requiredPredecessors = new Set(stage.predecessor_stage_ids);
  for (const edge of registry.feedback_edges.filter(item => item.to_stage_id === stage.stage_id)) {
    if (manifest.activated_conditions.includes(edge.condition_id)) requiredPredecessors.add(edge.from_stage_id);
  }
  for (const predecessorId of requiredPredecessors) {
    if (!predecessorIds.has(predecessorId)) errors.push(`stage-delivery-predecessor-missing:${predecessorId}`);
  }
  for (const predecessorId of predecessorIds) {
    if (!requiredPredecessors.has(predecessorId)) errors.push(`stage-delivery-predecessor-unexpected:${predecessorId}`);
  }

  validateArtifactBindings(manifest.input_artifacts, stage.input_artifacts, manifest, "input", errors);
  validateArtifactBindings(manifest.output_artifacts, stage.output_artifacts, manifest, "output", errors);

  if (!Array.isArray(manifest.validation_results)) errors.push("stage-delivery-validation-results-invalid");
  const validatorMap = new Map(stage.validators.map(validator => [validator.validator_id, validator]));
  const validationStatuses = new Map();
  for (const result of manifest.validation_results ?? []) {
    if (!exactKeys(result, ["validator_id", "status", "checked_artifact_types", "evidence_refs", "issues"])
      || !validatorMap.has(result.validator_id)
      || validationStatuses.has(result.validator_id)
      || !VALIDATION_STATUSES.has(result.status)
      || !uniqueStrings(result.checked_artifact_types, { required: true })
      || !uniqueStrings(result.evidence_refs)
      || !uniqueStrings(result.issues)) {
      errors.push("stage-delivery-validation-result-invalid");
      continue;
    }
    const template = validatorMap.get(result.validator_id);
    if (result.checked_artifact_types.some(type => !template.artifact_types.includes(type))) {
      errors.push(`stage-delivery-validation-artifact-type-invalid:${result.validator_id}`);
    }
    validationStatuses.set(result.validator_id, result.status);
  }
  const requiredValidatorIds = new Set(stage.validators
    .filter(validator => validator.requirement === "REQUIRED"
      || (validator.requirement === "CONDITIONAL" && manifest.activated_conditions.includes(validator.condition_id)))
    .map(validator => validator.validator_id));
  for (const validatorId of requiredValidatorIds) {
    if (!validationStatuses.has(validatorId)) errors.push(`stage-delivery-validation-result-missing:${validatorId}`);
  }

  validateGaps(manifest.gaps, errors);
  if (!exactKeys(manifest.producer, ["agent_name", "agent_session_id", "internal_stage_ids", "stage_agent_contract_ids"])
    || !nonEmptyString(manifest.producer?.agent_name)
    || !nonEmptyString(manifest.producer?.agent_session_id)
    || !uniqueStrings(manifest.producer?.internal_stage_ids, { required: true })
    || !uniqueStrings(manifest.producer?.stage_agent_contract_ids, { required: true })
    || manifest.producer.internal_stage_ids.some(id => !stage.internal_stage_ids.includes(id))
    || manifest.producer.stage_agent_contract_ids.some(id => !stage.stage_agent_contract_ids.includes(id))) {
    errors.push("stage-delivery-producer-invalid");
  }
  if (Number.isNaN(Date.parse(manifest.started_at))) errors.push("stage-delivery-started-at-invalid");
  if (!(manifest.completed_at === null || !Number.isNaN(Date.parse(manifest.completed_at)))) errors.push("stage-delivery-completed-at-invalid");

  const requiredOutputTypes = stage.output_artifacts
    .filter(artifact => artifact.requirement === "REQUIRED"
      || (artifact.requirement === "CONDITIONAL" && manifest.activated_conditions.includes(artifact.condition_id)))
    .map(artifact => artifact.artifact_type);
  const outputTypes = new Set(manifest.output_artifacts.map(artifact => artifact.artifact_type));
  const requiredOutputsSatisfied = requiredOutputTypes.every(type => outputTypes.has(type));
  const requiredValidatorsPassed = [...requiredValidatorIds].every(id => validationStatuses.get(id) === "PASS");
  const activeFeedbackEdges = registry.feedback_edges.filter(edge => edge.to_stage_id === stage.stage_id
    && manifest.activated_conditions.includes(edge.condition_id));
  const feedbackSourceIds = new Set(activeFeedbackEdges.map(edge => edge.from_stage_id));
  const forwardPredecessorsSatisfied = stage.predecessor_stage_ids.every(id => manifest.predecessor_manifests
    .some(item => item.stage_id === id && item.status === "COMPLETE"));
  const feedbackPredecessorsSatisfied = activeFeedbackEdges.every(edge => manifest.predecessor_manifests
    .some(item => item.stage_id === edge.from_stage_id && edge.allowed_source_statuses.includes(item.status)));
  const unexpectedCompleteFeedback = manifest.predecessor_manifests.some(item => feedbackSourceIds.has(item.stage_id)
    && !activeFeedbackEdges.some(edge => edge.from_stage_id === item.stage_id && edge.allowed_source_statuses.includes(item.status)));
  const predecessorsComplete = forwardPredecessorsSatisfied && feedbackPredecessorsSatisfied && !unexpectedCompleteFeedback;
  const zeroGaps = manifest.gaps.length === 0;
  const computedComplete = requiredOutputsSatisfied
    && requiredValidatorsPassed
    && (!stage.completion_gate.requires_predecessors_complete || predecessorsComplete)
    && (!stage.completion_gate.requires_zero_gaps || zeroGaps);
  if (!exactKeys(manifest.completion, ["required_outputs_satisfied", "required_validators_passed", "predecessors_complete", "complete"])
    || manifest.completion.required_outputs_satisfied !== requiredOutputsSatisfied
    || manifest.completion.required_validators_passed !== requiredValidatorsPassed
    || manifest.completion.predecessors_complete !== predecessorsComplete
    || manifest.completion.complete !== computedComplete) {
    errors.push("stage-delivery-completion-summary-invalid");
  }
  if (manifest.status === "COMPLETE") {
    if (!computedComplete) errors.push("stage-delivery-complete-gate-not-satisfied");
    if (manifest.completed_at === null) errors.push("stage-delivery-complete-completed-at-missing");
    if (manifest.scope_binding.state !== "FROZEN") errors.push("stage-delivery-complete-scope-not-frozen");
  } else {
    if (computedComplete) errors.push("stage-delivery-noncomplete-gate-satisfied");
    if (manifest.gaps.length === 0) errors.push("stage-delivery-noncomplete-gaps-missing");
  }
  if (!validDigest(manifest.manifest_digest) || manifest.manifest_digest !== stageDeliveryManifestDigest(manifest)) {
    errors.push("stage-delivery-manifest-digest-invalid");
  }
  return [...new Set(errors)];
}
