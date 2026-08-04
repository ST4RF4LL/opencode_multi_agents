#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  deriveFocusHandoffExpectations,
  stageEnvelopeDigest,
  validateStageContractRegistry,
  validateStageEnvelope,
  verifyStageHandoffs,
} from "../skills/common-subagent/audit-artifact-management/scripts/stage-agent-contract.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const OPENCODE = resolve(HERE, "..");
const REGISTRY_PATH = join(OPENCODE, "skills/common-subagent/audit-artifact-management/contracts/stage-agent-contracts.json");
const ROLES_PATH = join(OPENCODE, "agent-manifest/roles.json");
const DIGEST = "a".repeat(64);

function artifact(artifactType) {
  return {
    artifact_type: artifactType,
    path: `tmp/stage-contract-fixture/${artifactType}.json`,
    sha256: DIGEST,
    media_type: "application/json",
    json_pointer: null,
  };
}

function seal(envelope) {
  envelope.envelope_digest = stageEnvelopeDigest(envelope);
  return envelope;
}

async function main() {
  const [registry, roles] = await Promise.all([
    readFile(REGISTRY_PATH, "utf8").then(JSON.parse),
    readFile(ROLES_PATH, "utf8").then(JSON.parse),
  ]);
  assert.deepEqual(validateStageContractRegistry(registry, roles), []);
  assert.equal(registry.stages.length, 11);
  assert.equal(new Set(registry.contracts.map(contract => contract.agent_name)).size, Object.keys(roles.agents).length);

  const input = seal({
    schema_version: 1,
    contract_id: "P01_RECON.security-intel-collector",
    stage_id: "P01_RECON",
    direction: "INPUT",
    audit_id: "stage-contract-fixture",
    round: 1,
    agent_name: "security-intel-collector",
    agent_session_id: "intel-recon-r1",
    scope_binding: { state: "UNFROZEN", scope_digest: null },
    artifact_bindings: [],
    payload: {
      repository_path: "/fixture/repository",
      user_scope: ["src/main/java", "src/main/webapp"],
      constraints: ["static analysis only"],
      depth: "comprehensive",
    },
    constraints: ["Do not execute target code."],
  });
  assert.deepEqual(validateStageEnvelope(input, registry, { roles }), []);

  const requiredOutputArtifacts = registry.contracts
    .find(contract => contract.contract_id === input.contract_id)
    .output.required_artifact_types
    .map(artifact);
  const output = seal({
    schema_version: 1,
    contract_id: input.contract_id,
    stage_id: input.stage_id,
    direction: "OUTPUT",
    audit_id: input.audit_id,
    round: input.round,
    agent_name: input.agent_name,
    agent_session_id: input.agent_session_id,
    scope_binding: { state: "FROZEN", scope_digest: DIGEST },
    input_envelope_digest: input.envelope_digest,
    status: "COMPLETE",
    artifact_bindings: requiredOutputArtifacts,
    payload: {
      scope_digest: DIGEST,
      recon_state: "COMPLETE",
      languages: ["java", "javascript"],
      java_web_profile: true,
      gaps: [],
    },
    gaps: [],
  });
  assert.deepEqual(validateStageEnvelope(output, registry, { roles, inputEnvelope: input }), []);

  const missingArtifact = structuredClone(output);
  missingArtifact.artifact_bindings.pop();
  missingArtifact.envelope_digest = stageEnvelopeDigest(missingArtifact);
  assert(validateStageEnvelope(missingArtifact, registry, { roles, inputEnvelope: input })
    .some(error => error.startsWith("stage-envelope-required-artifact-missing:")));

  const partial = structuredClone(missingArtifact);
  partial.status = "PARTIAL";
  partial.gaps = [{
    gap_id: "GAP-RECON-001",
    category: "parser",
    description: "The Java parser capability probe failed.",
    blocking: true,
    evidence_refs: ["parser-capabilities"],
  }];
  partial.payload.gaps = ["GAP-RECON-001"];
  partial.envelope_digest = stageEnvelopeDigest(partial);
  assert.deepEqual(validateStageEnvelope(partial, registry, { roles, inputEnvelope: input }), []);

  const unexpectedPayload = structuredClone(input);
  unexpectedPayload.payload.uncontracted_field = true;
  unexpectedPayload.envelope_digest = stageEnvelopeDigest(unexpectedPayload);
  assert(validateStageEnvelope(unexpectedPayload, registry, { roles }).includes("stage-envelope-payload-field-not-allowed"));

  const focusManifest = {
    required_lenses: ["sink-driven", "control-driven", "config-driven"],
    focus_areas: [{
      focus_area_id: "FA-001",
      required_discovery_tracks: ["coverage", "blind"],
      assignments: [{
        assignment_id: "FA-001-java-base",
        agent_name: "java-source-auditor",
      }],
    }],
  };
  const focusExpectations = deriveFocusHandoffExpectations(focusManifest, registry, 1);
  assert.equal(focusExpectations.length, 4);
  const incompleteWorkflow = verifyStageHandoffs({
    registry,
    roles,
    focusManifest,
    handoffs: [{ path: "recon.output.json", input, output }],
    round: 1,
    throughStageId: "P04_FOCUS_EXECUTION",
  });
  assert.equal(incompleteWorkflow.complete, false);
  assert(incompleteWorkflow.missing.some(item => item.expectation_id === "coverage:FA-001:FA-001-java-base:sink-driven:r1"));
  assert(incompleteWorkflow.missing.some(item => item.expectation_id === "discovery:FA-001:blind:r1"));

  for (const [agentName, role] of Object.entries(roles.agents)) {
    const text = await readFile(join(OPENCODE, "agents", `${agentName}.md`), "utf8");
    for (const contractId of role.stage_contract_ids) {
      assert(text.includes(contractId), `${agentName} does not name stage contract ${contractId}`);
    }
  }

  process.stdout.write(`${JSON.stringify({
    complete: true,
    stage_agent_contract: "v1",
    stages: registry.stages.length,
    contracts: registry.contracts.length,
    agents: Object.keys(roles.agents).length,
    cases: 8,
  })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
