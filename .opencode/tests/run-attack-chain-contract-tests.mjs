#!/usr/bin/env node

import { strict as assert } from "node:assert";
import {
  attackChainManifestDigest,
  validateAttackChainManifest,
} from "../skills/attack-chain-subagent/system-attack-chain-hunting/scripts/attack-chain-contract.mjs";

const DIGEST = "a".repeat(64);
const ADJUDICATION = {
  manifest_digest: "b".repeat(64),
  decisions: [{ finding_id: "FIND-CHAIN-001", state: "SUPPORTED_STATIC" }],
};

function chain(overrides = {}) {
  return {
    chain_id: "CHAIN-001",
    assessment_state: "SUPPORTED_STATIC",
    steps: [{
      step_id: "S1",
      claim: "The adjudicated finding exposes an outbound request capability.",
      evidence_state: "SUPPORTED_STATIC",
      evidence_refs: ["FIND-CHAIN-001"],
      blocking_gap_ids: [],
    }],
    transitions: [],
    first_blocking_step_id: null,
    ...overrides,
  };
}

function manifestWith(chains, gaps = []) {
  const manifest = {
    schema_version: 2,
    audit_id: "chain-fixture",
    scope_digest: DIGEST,
    adjudication_manifest_digest: ADJUDICATION.manifest_digest,
    chains,
    gaps,
    chain_accounting: {
      raw_chain_ids: chains.map(item => item.chain_id),
      accepted_chain_ids: chains.filter(item => ["CONDITIONAL", "SUPPORTED_STATIC", "SUPPORTED_RUNTIME"].includes(item.assessment_state)).map(item => item.chain_id),
      rejected_chain_ids: chains.filter(item => item.assessment_state === "CONTRADICTED").map(item => item.chain_id),
    },
  };
  manifest.manifest_digest = attackChainManifestDigest(manifest);
  return manifest;
}

function expectError(errors, expected) {
  assert(errors.includes(expected), `Expected ${expected}; got ${errors.join(", ")}`);
}

async function main() {
  const supported = manifestWith([chain()]);
  assert.deepEqual(validateAttackChainManifest(supported, ADJUDICATION), []);

  const conditionalChain = chain({
    chain_id: "CHAIN-002",
    assessment_state: "CONDITIONAL",
    steps: [{
      step_id: "S1",
      claim: "The management endpoint is externally exposed.",
      evidence_state: "DEPLOYMENT_UNKNOWN",
      evidence_refs: [],
      blocking_gap_ids: ["GAP-CHAIN-002-S1"],
    }],
    first_blocking_step_id: "S1",
  });
  const conditional = manifestWith([conditionalChain], [{ gap_id: "GAP-CHAIN-002-S1", chain_ids: ["CHAIN-002"] }]);
  assert.deepEqual(validateAttackChainManifest(conditional, ADJUDICATION), []);

  const overclaimed = manifestWith([chain({
    assessment_state: "SUPPORTED_STATIC",
    steps: conditionalChain.steps,
    first_blocking_step_id: "S1",
  })], [{ gap_id: "GAP-CHAIN-002-S1", chain_ids: ["CHAIN-001"] }]);
  expectError(validateAttackChainManifest(overclaimed, ADJUDICATION), "chain:CHAIN-001:assessment-state-mismatch");

  const unaudited = manifestWith([chain({
    steps: [{
      ...chain().steps[0],
      evidence_refs: ["FIND-UNADJUDICATED"],
    }],
  })]);
  expectError(validateAttackChainManifest(unaudited, ADJUDICATION), "chain:CHAIN-001:step-evidence-not-adjudicated");

  process.stdout.write(`${JSON.stringify({ complete: true, attack_chain_contract: "v2", cases: 4 })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
