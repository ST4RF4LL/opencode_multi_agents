#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");
const SUITE_PATH = resolve(ROOT, ".opencode/shared/security-audit/adjudication-regressions/mall-v1-semantic-twins.json");
const FRAMEWORK_MODELS_PATH = resolve(ROOT, ".opencode/skills/common-subagent/finding-adjudication/references/framework-semantic-models.md");

const REQUIRED_MODELS = new Map([
  ["jwt", "Actual dependency"],
  ["object_storage_path", "Storage API semantics"],
  ["log_injection", "real logger"],
  ["mass_assignment", "Broad bind"],
  ["spring_rbac", "Registration/default role"],
  ["actuator", "Boot version"],
  ["cors", "Origin rule"],
  ["url_ssrf_redirect", "HTTP client"],
]);
const FALSE_POSITIVE_OUTCOMES = new Set(["REJECTED", "INCONCLUSIVE", "RECLASSIFIED"]);

function nonEmpty(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function validateTwin(twin, expectedLabel, permittedStates) {
  assert(twin && typeof twin === "object", `${expectedLabel} twin is missing`);
  assert(nonEmpty(twin.id), `${expectedLabel} twin id is missing`);
  assert(permittedStates.has(twin.expected_state), `${twin.id} has an invalid expected state`);
  assert(nonEmpty(twin.source_excerpt), `${twin.id} lacks a source or synthetic twin excerpt`);
  assert(Array.isArray(twin.required_evidence) && twin.required_evidence.length >= 3
    && twin.required_evidence.every(nonEmpty), `${twin.id} lacks a minimally independent semantic evidence set`);
  assert(nonEmpty(twin.reason), `${twin.id} lacks an adjudication rationale`);
  assert(!/\bCONFIRMED\b/.test(twin.expected_state), `${twin.id} retains the forbidden CONFIRMED state`);
}

async function main() {
  const [suite, frameworkModels, sourceReport] = await Promise.all([
    readFile(SUITE_PATH, "utf8").then(JSON.parse),
    readFile(FRAMEWORK_MODELS_PATH, "utf8"),
    readFile(resolve(ROOT, "reports/final/security-audit-report.mall-v1.md"), "utf8"),
  ]);
  assert(suite.schema_version === 1 && suite.suite_id === "mall-v1-semantic-twins", "Mall semantic twin suite identity is invalid");
  assert(Array.isArray(suite.models) && suite.models.length === REQUIRED_MODELS.size, "Mall suite must contain exactly the eight semantic model twins");
  assert(!/\bCONFIRMED\b/.test(JSON.stringify(suite)), "Mall twin suite must use adjudication states, not CONFIRMED");

  const seenModels = new Set();
  const seenTwinIds = new Set();
  for (const model of suite.models) {
    assert(REQUIRED_MODELS.has(model.model_id), `Unexpected or duplicate semantic model: ${model.model_id}`);
    assert(!seenModels.has(model.model_id), `Duplicate semantic model: ${model.model_id}`);
    seenModels.add(model.model_id);
    assert(frameworkModels.includes(REQUIRED_MODELS.get(model.model_id)), `${model.model_id} lacks its framework semantic checklist`);
    assert(Array.isArray(model.historical_ids) && model.historical_ids.length > 0, `${model.model_id} lacks a mall-v1 historical anchor`);
    for (const findingId of model.historical_ids) assert(sourceReport.includes(findingId), `${model.model_id} references an unknown historical finding: ${findingId}`);
    validateTwin(model.false_positive, `${model.model_id} false-positive`, FALSE_POSITIVE_OUTCOMES);
    validateTwin(model.true_positive, `${model.model_id} true-positive`, new Set(["SUPPORTED_STATIC", "SUPPORTED_RUNTIME"]));
    for (const twin of [model.false_positive, model.true_positive]) {
      assert(!seenTwinIds.has(twin.id), `Duplicate twin id: ${twin.id}`);
      seenTwinIds.add(twin.id);
    }
  }
  assert.deepEqual(seenModels, new Set(REQUIRED_MODELS.keys()), "Mall suite omits a required semantic model");
  assert(Array.isArray(suite.chain_regressions) && suite.chain_regressions.length === 3, "Mall suite must retain the three historically overclaimed chains");
  for (const chain of suite.chain_regressions) {
    assert(nonEmpty(chain.id) && chain.expected_state === "CONDITIONAL"
      && Array.isArray(chain.missing_conditions) && chain.missing_conditions.length >= 3,
    `Chain regression is not conservatively conditional: ${chain.id ?? "unknown"}`);
  }
  process.stdout.write(`${JSON.stringify({ complete: true, suite: suite.suite_id, models: seenModels.size, twins: seenTwinIds.size, conditional_chains: suite.chain_regressions.length })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
