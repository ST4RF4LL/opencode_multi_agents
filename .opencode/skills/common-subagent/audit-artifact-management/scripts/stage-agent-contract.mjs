import { createHash } from "node:crypto";

export const STAGE_AGENT_ENVELOPE_SCHEMA_VERSION = 1;

const INVOCATION_MODES = new Set([
  "REQUIRED_ONCE",
  "REQUIRED_PER_ROUND",
  "REPEATABLE_FROM_PLAN",
  "REPEATABLE_FROM_GAPS",
  "REQUIRED_ONCE_WHEN_CANDIDATES_EXIST",
  "REQUIRED_FOR_TERMINAL_REPORT",
  "CONDITIONAL",
]);
const SCOPE_STATES = new Set(["UNFROZEN", "FROZEN"]);
const DIRECTIONS = new Set(["INPUT", "OUTPUT"]);

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

export function stageEnvelopeDigest(envelope) {
  const copy = structuredClone(envelope);
  delete copy.envelope_digest;
  return createHash("sha256").update(JSON.stringify(canonicalize(copy))).digest("hex");
}

function exactKeys(value, expected) {
  return isObject(value)
    && Object.keys(value).length === expected.length
    && expected.every(key => Object.hasOwn(value, key));
}

function validateTemplateSide(side, prefix, errors) {
  if (!isObject(side)) {
    errors.push(`${prefix}-template-missing`);
    return;
  }
  for (const field of [
    "required_artifact_types",
    "optional_artifact_types",
    "required_payload_fields",
    "optional_payload_fields",
  ]) {
    if (!uniqueStrings(side[field])) errors.push(`${prefix}-${field.replaceAll("_", "-")}-invalid`);
  }
  const artifacts = [...(side.required_artifact_types ?? []), ...(side.optional_artifact_types ?? [])];
  const payload = [...(side.required_payload_fields ?? []), ...(side.optional_payload_fields ?? [])];
  if (new Set(artifacts).size !== artifacts.length) errors.push(`${prefix}-artifact-types-overlap`);
  if (new Set(payload).size !== payload.length) errors.push(`${prefix}-payload-fields-overlap`);
}

export function validateStageContractRegistry(registry, roles = null) {
  const errors = [];
  if (!isObject(registry)) return ["stage-contract-registry-not-object"];
  if (registry.schema_version !== STAGE_AGENT_ENVELOPE_SCHEMA_VERSION) errors.push("stage-contract-registry-schema-version-invalid");
  if (!nonEmptyString(registry.purpose)) errors.push("stage-contract-registry-purpose-missing");
  if (!Array.isArray(registry.stages) || registry.stages.length === 0) errors.push("stage-contract-registry-stages-missing");
  if (!Array.isArray(registry.contracts) || registry.contracts.length === 0) errors.push("stage-contract-registry-contracts-missing");
  if (!isObject(registry.envelope)
    || registry.envelope.schema_version !== STAGE_AGENT_ENVELOPE_SCHEMA_VERSION
    || !nonEmptyString(registry.envelope.input_path_template)
    || !nonEmptyString(registry.envelope.output_path_template)
    || !uniqueStrings(registry.envelope.statuses, { required: true })) {
    errors.push("stage-contract-registry-envelope-invalid");
  }

  const stages = new Map();
  const orders = new Set();
  for (const stage of registry.stages ?? []) {
    if (!isObject(stage)
      || !nonEmptyString(stage.stage_id)
      || stages.has(stage.stage_id)
      || !Number.isInteger(stage.order)
      || orders.has(stage.order)
      || !nonEmptyString(stage.name)) {
      errors.push("stage-contract-registry-stage-invalid");
    } else {
      stages.set(stage.stage_id, stage);
      orders.add(stage.order);
    }
  }

  const contracts = new Map();
  const roleNames = roles && isObject(roles.agents) ? new Set(Object.keys(roles.agents)) : null;
  for (const contract of registry.contracts ?? []) {
    const id = contract?.contract_id;
    if (!isObject(contract) || !nonEmptyString(id) || contracts.has(id)) {
      errors.push("stage-contract-registry-contract-id-invalid");
      continue;
    }
    contracts.set(id, contract);
    if (!stages.has(contract.stage_id)) errors.push(`contract:${id}:stage-invalid`);
    if (!nonEmptyString(contract.agent_name) || (roleNames && !roleNames.has(contract.agent_name))) {
      errors.push(`contract:${id}:agent-invalid`);
    }
    if (!INVOCATION_MODES.has(contract.invocation)) errors.push(`contract:${id}:invocation-invalid`);
    if (!SCOPE_STATES.has(contract.input_scope_state) || !SCOPE_STATES.has(contract.output_scope_state)) {
      errors.push(`contract:${id}:scope-state-invalid`);
    }
    validateTemplateSide(contract.input, `contract:${id}:input`, errors);
    validateTemplateSide(contract.output, `contract:${id}:output`, errors);
  }

  if (roleNames) {
    for (const agentName of roleNames) {
      const expected = [...contracts.values()]
        .filter(contract => contract.agent_name === agentName)
        .map(contract => contract.contract_id)
        .sort();
      const declared = roles.agents[agentName]?.stage_contract_ids;
      if (expected.length === 0) errors.push(`role:${agentName}:stage-contract-missing`);
      if (!Array.isArray(declared)
        || declared.length !== expected.length
        || new Set(declared).size !== declared.length
        || !expected.every(id => declared.includes(id))) {
        errors.push(`role:${agentName}:stage-contract-ids-mismatch`);
      }
    }
  }
  return [...new Set(errors)];
}

function validateScopeBinding(binding, expectedState, errors) {
  if (!exactKeys(binding, ["state", "scope_digest"]) || binding.state !== expectedState) {
    errors.push("stage-envelope-scope-binding-invalid");
    return;
  }
  if ((binding.state === "FROZEN" && !validDigest(binding.scope_digest))
    || (binding.state === "UNFROZEN" && binding.scope_digest !== null)) {
    errors.push("stage-envelope-scope-binding-invalid");
  }
}

function validateArtifactBindings(bindings, errors) {
  if (!Array.isArray(bindings)) {
    errors.push("stage-envelope-artifact-bindings-missing");
    return new Set();
  }
  const identities = new Set();
  const types = new Set();
  for (const binding of bindings) {
    if (!exactKeys(binding, ["artifact_type", "path", "sha256", "media_type", "json_pointer"])
      || !nonEmptyString(binding.artifact_type)
      || !nonEmptyString(binding.path)
      || !validDigest(binding.sha256)
      || !nonEmptyString(binding.media_type)
      || !(binding.json_pointer === null
        || (nonEmptyString(binding.json_pointer) && binding.json_pointer.startsWith("/")))) {
      errors.push("stage-envelope-artifact-binding-invalid");
      continue;
    }
    const identity = `${binding.artifact_type}|${binding.path}|${binding.json_pointer ?? ""}`;
    if (identities.has(identity)) errors.push("stage-envelope-artifact-binding-duplicate");
    identities.add(identity);
    types.add(binding.artifact_type);
  }
  return types;
}

function validatePayload(payload, template, errors) {
  if (!isObject(payload)) {
    errors.push("stage-envelope-payload-invalid");
    return;
  }
  const required = template.required_payload_fields;
  const allowed = new Set([...required, ...template.optional_payload_fields]);
  if (required.some(field => !Object.hasOwn(payload, field))) errors.push("stage-envelope-payload-required-field-missing");
  if (Object.keys(payload).some(field => !allowed.has(field))) errors.push("stage-envelope-payload-field-not-allowed");
}

function validateGaps(gaps, errors) {
  if (!Array.isArray(gaps)) {
    errors.push("stage-envelope-gaps-missing");
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
      errors.push("stage-envelope-gap-invalid");
    } else {
      ids.add(gap.gap_id);
    }
  }
}

export function validateStageEnvelope(envelope, registry, context = {}) {
  const errors = [];
  if (!isObject(envelope)) return ["stage-envelope-not-object"];
  const registryErrors = validateStageContractRegistry(registry, context.roles ?? null);
  if (registryErrors.length > 0) return registryErrors.map(error => `registry:${error}`);
  if (envelope.schema_version !== STAGE_AGENT_ENVELOPE_SCHEMA_VERSION) errors.push("stage-envelope-schema-version-invalid");
  if (!DIRECTIONS.has(envelope.direction)) errors.push("stage-envelope-direction-invalid");
  const contract = (registry.contracts ?? []).find(item => item.contract_id === envelope.contract_id);
  if (!contract) return [...errors, "stage-envelope-contract-unknown"];
  if (envelope.stage_id !== contract.stage_id) errors.push("stage-envelope-stage-id-mismatch");
  if (envelope.agent_name !== contract.agent_name) errors.push("stage-envelope-agent-name-mismatch");
  if (!nonEmptyString(envelope.audit_id)) errors.push("stage-envelope-audit-id-missing");
  if (!Number.isInteger(envelope.round) || envelope.round < 0) errors.push("stage-envelope-round-invalid");
  if (!nonEmptyString(envelope.agent_session_id)) errors.push("stage-envelope-agent-session-id-missing");

  const inputKeys = [
    "schema_version",
    "contract_id",
    "stage_id",
    "direction",
    "audit_id",
    "round",
    "agent_name",
    "agent_session_id",
    "scope_binding",
    "artifact_bindings",
    "payload",
    "constraints",
    "envelope_digest",
  ];
  const outputKeys = [
    "schema_version",
    "contract_id",
    "stage_id",
    "direction",
    "audit_id",
    "round",
    "agent_name",
    "agent_session_id",
    "scope_binding",
    "input_envelope_digest",
    "status",
    "artifact_bindings",
    "payload",
    "gaps",
    "envelope_digest",
  ];
  const expectedKeys = envelope.direction === "OUTPUT" ? outputKeys : inputKeys;
  if (!exactKeys(envelope, expectedKeys)) errors.push("stage-envelope-fields-not-exact");

  const side = envelope.direction === "OUTPUT" ? contract.output : contract.input;
  const scopeState = envelope.direction === "OUTPUT" ? contract.output_scope_state : contract.input_scope_state;
  validateScopeBinding(envelope.scope_binding, scopeState, errors);
  const artifactTypes = validateArtifactBindings(envelope.artifact_bindings, errors);
  validatePayload(envelope.payload, side, errors);

  if (envelope.direction === "INPUT") {
    if (!uniqueStrings(envelope.constraints)) errors.push("stage-envelope-constraints-invalid");
    for (const type of side.required_artifact_types) {
      if (!artifactTypes.has(type)) errors.push(`stage-envelope-required-artifact-missing:${type}`);
    }
  } else {
    if (!registry.envelope.statuses.includes(envelope.status)) errors.push("stage-envelope-status-invalid");
    if (!validDigest(envelope.input_envelope_digest)) errors.push("stage-envelope-input-digest-invalid");
    validateGaps(envelope.gaps, errors);
    const gapCount = Array.isArray(envelope.gaps) ? envelope.gaps.length : 0;
    if (envelope.status === "COMPLETE") {
      if (gapCount > 0) errors.push("stage-envelope-complete-has-gaps");
      for (const type of side.required_artifact_types) {
        if (!artifactTypes.has(type)) errors.push(`stage-envelope-required-artifact-missing:${type}`);
      }
    } else if (gapCount === 0) {
      errors.push("stage-envelope-noncomplete-gaps-missing");
    }
    if (context.inputEnvelope) {
      const inputErrors = validateStageEnvelope(context.inputEnvelope, registry, {
        roles: context.roles,
        requireDigest: true,
      });
      if (inputErrors.length > 0) errors.push("stage-envelope-bound-input-invalid");
      if (envelope.input_envelope_digest !== context.inputEnvelope.envelope_digest) errors.push("stage-envelope-bound-input-digest-mismatch");
      for (const field of ["contract_id", "stage_id", "audit_id", "round", "agent_name", "agent_session_id"]) {
        if (envelope[field] !== context.inputEnvelope[field]) errors.push(`stage-envelope-bound-input-${field.replaceAll("_", "-")}-mismatch`);
      }
    }
  }
  if (context.requireDigest !== false && envelope.envelope_digest !== stageEnvelopeDigest(envelope)) {
    errors.push("stage-envelope-digest-invalid");
  }
  return [...new Set(errors)];
}

export function deriveFocusHandoffExpectations(focusManifest, registry, round) {
  if (!isObject(focusManifest) || !Array.isArray(focusManifest.focus_areas)
    || !uniqueStrings(focusManifest.required_lenses, { required: true })
    || !Number.isInteger(round) || round < 1) {
    throw new Error("Focus manifest or round is invalid");
  }
  const contractIdsByAgent = new Map(registry.contracts
    .filter(contract => contract.stage_id === "P04_FOCUS_EXECUTION")
    .map(contract => [contract.agent_name, contract.contract_id]));
  const expectations = [];
  for (const focus of focusManifest.focus_areas) {
    for (const assignment of focus.assignments ?? []) {
      const contractId = contractIdsByAgent.get(assignment.agent_name);
      if (!contractId) throw new Error(`Focus assignment has no P04 contract: ${assignment.agent_name}`);
      for (const lens of focusManifest.required_lenses) {
        expectations.push({
          expectation_id: `coverage:${focus.focus_area_id}:${assignment.assignment_id}:${lens}:r${round}`,
          kind: "FOCUS_COVERAGE",
          contract_id: contractId,
          round,
          match: {
            focus_area_id: focus.focus_area_id,
            assignment_id: assignment.assignment_id,
            discovery_track: "coverage",
            audit_strategy: lens,
          },
        });
      }
    }
    const assignmentAgents = [...new Set((focus.assignments ?? []).map(assignment => assignment.agent_name))];
    for (const track of focus.required_discovery_tracks ?? []) {
      if (track === "coverage") continue;
      expectations.push({
        expectation_id: `discovery:${focus.focus_area_id}:${track}:r${round}`,
        kind: "FOCUS_DISCOVERY",
        contract_ids: assignmentAgents.map(agent => contractIdsByAgent.get(agent)).filter(Boolean),
        round,
        match: {
          focus_area_id: focus.focus_area_id,
          discovery_track: track,
        },
      });
    }
  }
  return expectations;
}

function outputMatchesExpectation(output, expectation) {
  const contractIds = expectation.contract_ids ?? [expectation.contract_id];
  return output?.direction === "OUTPUT"
    && output.status === "COMPLETE"
    && output.round === expectation.round
    && contractIds.includes(output.contract_id)
    && Object.entries(expectation.match ?? []).every(([key, value]) => output.payload?.[key] === value);
}

export function verifyStageHandoffs({
  registry,
  roles,
  focusManifest,
  handoffs,
  round,
  throughStageId = "P08_FINALIZE",
  candidateCount = 0,
}) {
  const registryErrors = validateStageContractRegistry(registry, roles);
  if (registryErrors.length > 0) throw new Error(`Registry is invalid: ${registryErrors.join(", ")}`);
  const stageOrder = new Map(registry.stages.map(stage => [stage.stage_id, stage.order]));
  const throughOrder = stageOrder.get(throughStageId);
  if (!Number.isInteger(throughOrder)) throw new Error(`Unknown through stage: ${throughStageId}`);
  const invalid = [];
  const validOutputs = [];
  for (const [index, handoff] of (handoffs ?? []).entries()) {
    if (!handoff?.input) {
      invalid.push({
        handoff: handoff?.path ?? `handoff:${index}`,
        contract_id: handoff?.output?.contract_id ?? null,
        errors: ["stage-envelope-bound-input-missing"],
      });
      continue;
    }
    const errors = validateStageEnvelope(handoff?.output, registry, {
      roles,
      inputEnvelope: handoff?.input,
    });
    if (errors.length > 0) {
      invalid.push({
        handoff: handoff?.path ?? `handoff:${index}`,
        contract_id: handoff?.output?.contract_id ?? null,
        errors,
      });
    } else {
      validOutputs.push(handoff.output);
    }
  }

  const fixedExpectations = registry.contracts
    .filter(contract => stageOrder.get(contract.stage_id) <= throughOrder)
    .filter(contract => {
      if (contract.contract_id === "P08_FINALIZE.security-audit-orchestrator") return false;
      if (["REQUIRED_ONCE", "REQUIRED_PER_ROUND", "REQUIRED_FOR_TERMINAL_REPORT"].includes(contract.invocation)) return true;
      return contract.invocation === "REQUIRED_ONCE_WHEN_CANDIDATES_EXIST" && candidateCount > 0;
    })
    .map(contract => ({
      expectation_id: `fixed:${contract.contract_id}${contract.invocation === "REQUIRED_PER_ROUND" ? `:r${round}` : ""}`,
      kind: "FIXED_STAGE",
      contract_id: contract.contract_id,
      round: contract.invocation === "REQUIRED_PER_ROUND" ? round : null,
    }));
  const focusExpectations = stageOrder.get("P04_FOCUS_EXECUTION") <= throughOrder
    ? deriveFocusHandoffExpectations(focusManifest, registry, round)
    : [];
  const expected = [...fixedExpectations, ...focusExpectations];
  const missing = [];
  for (const expectation of expected) {
    const matched = expectation.kind === "FIXED_STAGE"
      ? validOutputs.some(output => output.status === "COMPLETE"
        && output.contract_id === expectation.contract_id
        && (expectation.round == null || output.round === expectation.round))
      : validOutputs.some(output => outputMatchesExpectation(output, expectation));
    if (!matched) missing.push(expectation);
  }
  return {
    expected,
    observed_complete_output_digests: validOutputs
      .filter(output => output.status === "COMPLETE")
      .map(output => output.envelope_digest)
      .sort(),
    missing,
    invalid,
    complete: missing.length === 0 && invalid.length === 0,
  };
}
