#!/usr/bin/env node

import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { Client } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js";
import { StdioClientTransport } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js";
import {
  COVERAGE_EXECUTION_MODEL,
  COVERAGE_MODEL_VERSION,
  PLAN_SCHEMA_VERSION,
  coverageCheckId,
  coverageUnitId,
  interfaceGroupId,
  objectDigest,
  sha256,
  sourceSetId,
  validatePlan,
} from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-v2-common.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPOSITORY = resolve(HERE, "../..");
const SERVER = join(REPOSITORY, ".opencode/mcp/coverage-ledger-server.mjs");
const AUDIT_ID = "coverage-large-response-fixture";
const RESPONSE_LIMIT = 16 * 1024;
const SOURCE_COUNT = 5_000;
const LENSES = ["sink-driven", "control-driven", "config-driven"];

function makePlan() {
  const sourceIndex = Array.from({ length: SOURCE_COUNT }, (_, index) => ({
    file_id: `file:${sha256(`file-${index}`).slice(0, 24)}`,
    path: `src/generated/file-${String(index).padStart(5, "0")}.js`,
    type: "file",
    sha256: sha256(`source-${index}`),
    link_target: null,
    owner_agent: "web-source-auditor",
  })).sort((left, right) => left.file_id.localeCompare(right.file_id));
  const sourceIds = sourceIndex.map(source => source.file_id).sort();
  const interfaceIndex = sourceIndex.map((source, index) => ({
    interface_id: `interface:${sha256(`interface-${index}`).slice(0, 24)}`,
    file_id: source.file_id,
    direction: "ingress",
    kind: "http",
    protocol: "http",
    operation: "GET",
    address: `/generated/${index}`,
    line_start: 1,
    dimensions: ["D1"],
  })).sort((left, right) => left.interface_id.localeCompare(right.interface_id));
  const interfaceIds = interfaceIndex.map(item => item.interface_id);
  const subjectId = interfaceGroupId("FA-LARGE", "web", "JW-TEST-01", interfaceIds);
  const frozenSourceSetId = sourceSetId(sourceIds);
  const checks = LENSES.map(lens => ({
    check_id: coverageCheckId("interface", subjectId, "JW-TEST-01", "web", lens),
    subject_kind: "interface",
    subject_id: subjectId,
    vulnerability_type_id: "JW-TEST-01",
    domain: "web",
    lens,
    focus_area_id: "FA-LARGE",
    dimensions: ["D1"],
    applicability: "REQUIRED",
    applicability_reason: "large-source-response-regression",
    negative_discovery_required: false,
    required_source_set_id: frozenSourceSetId,
    required_source_count: sourceIds.length,
    required_interface_ids: interfaceIds,
    required_catalog_ids: ["JW-TEST-01"],
    evidence_contract: {
      question_field: `${lens.replace("-driven", "")}_question`,
      question: "Was the complete frozen source universe reviewed?",
      required_receipt_fields: ["source_set_id", "locators", "query_or_rule", "tool", "result_attestation"],
    },
  }));
  checks.sort((left, right) => left.check_id.localeCompare(right.check_id));
  const assignmentId = "assignment:large-response-fixture";
  const unitId = coverageUnitId(assignmentId, "FA-LARGE", "web", checks.map(check => check.check_id));
  const coverageUnits = [{
    unit_id: unitId,
    assignment_id: assignmentId,
    focus_area_id: "FA-LARGE",
    domain: "web",
    agent_name: "web-source-auditor",
    required_lenses: LENSES,
    check_ids: checks.map(check => check.check_id),
    check_set_sha256: sha256(JSON.stringify(checks.map(check => check.check_id))),
    required_check_count: checks.length,
    required_source_set_id: frozenSourceSetId,
    required_source_count: sourceIds.length,
    required_catalog_count: 1,
    required_interface_count: interfaceIds.length,
    policy_tags: ["external-interface"],
  }];
  const plan = {
    schema_version: PLAN_SCHEMA_VERSION,
    coverage_model_version: COVERAGE_MODEL_VERSION,
    execution_model: COVERAGE_EXECUTION_MODEL,
    coverage_policy: {
      mode: "observe",
      release_required_unit_ids: [unitId],
      assurance_requires_all_checks: true,
    },
    audit_id: AUDIT_ID,
    catalog_profile_id: "response-fixture-v4",
    scope_digest: sha256("large-response-scope"),
    required_lenses: LENSES,
    inputs: { snapshot_digest: sha256("large-response-snapshot") },
    source_index: sourceIndex,
    source_sets: [{ source_set_id: frozenSourceSetId, file_ids: sourceIds }],
    interface_index: interfaceIndex,
    universes: {
      files: SOURCE_COUNT,
      function_files: 0,
      functions: 0,
      interfaces: SOURCE_COUNT,
      interface_anchors: SOURCE_COUNT,
      vulnerability_types: 1,
      active_domains: ["web"],
    },
    inventory: {
      eligible_files: SOURCE_COUNT,
      resolved_files: SOURCE_COUNT,
      gap_files: 0,
      gap_file_ids: [],
      confirmed_interfaces: SOURCE_COUNT,
      candidate_interfaces: 0,
      candidate_interface_ids: [],
      rejected_interfaces: 0,
      unresolved_interfaces: 0,
      extractor_complete: true,
      bounded: true,
    },
    checks,
    coverage_units: coverageUnits,
    summary: {
      atomic_checks: checks.length,
      required: checks.length,
      not_applicable: 0,
      unknown: 0,
      catalog_domain_required: 0,
      interface_required: checks.length,
      interface_memberships_required: checks.length * SOURCE_COUNT,
      coverage_units: coverageUnits.length,
    },
    complete: true,
  };
  plan.manifest_digest = objectDigest(plan);
  const errors = validatePlan(plan);
  if (errors.length > 0) throw new Error(`Large response fixture plan is invalid: ${errors.join("; ")}`);
  return plan;
}

async function main() {
  const workspace = await mkdtemp(join(tmpdir(), "opencode-coverage-response-"));
  const client = new Client({ name: "coverage-response-test", version: "1.0.0" });
  let connected = false;
  try {
    const plan = makePlan();
    const coverageDirectory = join(workspace, "reports", "coverage");
    await mkdir(coverageDirectory, { recursive: true });
    await writeFile(
      join(coverageDirectory, `coverage-plan.${AUDIT_ID}.json`),
      `${JSON.stringify(plan)}\n`,
      "utf8",
    );

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [SERVER],
      cwd: workspace,
      env: process.env,
    });
    await client.connect(transport);
    connected = true;

    async function call(name, args) {
      const result = await client.callTool({ name, arguments: args });
      const text = result.content?.find(item => item.type === "text")?.text ?? "";
      if (result.isError === true) throw new Error(`${name} failed: ${text}`);
      const responseBytes = Buffer.byteLength(text);
      if (responseBytes > RESPONSE_LIMIT) {
        throw new Error(`${name} returned ${responseBytes} bytes, above the ${RESPONSE_LIMIT}-byte contract`);
      }
      return { value: JSON.parse(text), responseBytes, text };
    }

    const unitPage = await call("coverage_get_unit", {
      audit_id: AUDIT_ID,
      limit: 10,
    });
    const unit = unitPage.value.units[0];
    if (unitPage.text.includes(plan.source_index[0].file_id)
      || unitPage.text.includes(plan.interface_index[0].interface_id)
      || unit.required_source_count !== SOURCE_COUNT
      || unit.required_interface_count !== SOURCE_COUNT
      || unit.required_check_count !== LENSES.length) {
      throw new Error("Coverage unit response leaked a frozen member list or omitted compact member counts");
    }

    const mutationStarted = performance.now();
    const assignment = await call("coverage_begin_unit", {
      audit_id: AUDIT_ID,
      unit_id: unit.unit_id,
      session_id: "large-response-session",
      agent_name: "web-source-auditor",
      idempotency_key: "large-response-unit-begin",
    });
    if (assignment.text.includes(plan.source_index[0].file_id)) {
      throw new Error("Coverage unit assignment leaked source metadata into the normal workflow");
    }

    const attestation = await call("coverage_submit_attestation", {
      audit_id: AUDIT_ID,
      unit_id: unit.unit_id,
      session_id: "large-response-session",
      assignment_token: assignment.value.assignment_token,
      idempotency_key: "large-response-attestation",
      completed_lenses: LENSES,
      state: "COMPLETE",
      gap_check_ids: [],
      source_scope: "required",
      query_or_rule: "large-response-regression",
      tool: "fixture",
      tool_version: "1.0.0",
      result_payload: "large-response-result",
      result_digest: sha256("large-response-result"),
      result_summary: "Complete frozen source set reviewed.",
    });
    if (!attestation.value.attestation.attestation_id) {
      throw new Error("Coverage unit attestation response omitted its compact identifier");
    }
    const gaps = await call("coverage_get_gaps", {
      audit_id: AUDIT_ID,
    });
    if (gaps.value.total_gaps !== 0 || gaps.value.verified !== plan.checks.length) {
      throw new Error("One complete unit attestation did not verify all internal member checks");
    }
    const mutationWorkflowMs = Number((performance.now() - mutationStarted).toFixed(2));

    const unitChecks = await call("coverage_get_unit_checks", {
      audit_id: AUDIT_ID,
      unit_id: unit.unit_id,
      limit: 10,
    });
    const check = unitChecks.value.checks[0];

    const diagnosticSources = await call("coverage_get_subject_sources", {
      audit_id: AUDIT_ID,
      check_id: check.check_id,
      limit: 25,
    });
    if (diagnosticSources.value.returned !== 25 || diagnosticSources.value.total_sources !== SOURCE_COUNT) {
      throw new Error("Targeted source diagnostics did not remain cursor-paginated");
    }
    const diagnosticInterfaces = await call("coverage_get_subject_interfaces", {
      audit_id: AUDIT_ID,
      check_id: check.check_id,
      limit: 25,
    });
    if (diagnosticInterfaces.value.returned !== 25
      || diagnosticInterfaces.value.total_interfaces !== SOURCE_COUNT
      || diagnosticInterfaces.text.includes(plan.interface_index[25].interface_id)) {
      throw new Error("Targeted interface diagnostics did not remain cursor-paginated");
    }

    const normalWorkflowBytes = unitPage.responseBytes
      + assignment.responseBytes
      + attestation.responseBytes;
    if (normalWorkflowBytes > RESPONSE_LIMIT) {
      throw new Error(`Normal source-set workflow returned ${normalWorkflowBytes} cumulative bytes`);
    }

    const ledgerPath = join(
      coverageDirectory,
      AUDIT_ID,
      "ledger",
      "coverage-ledger.jsonl",
    );
    const ledgerText = await readFile(ledgerPath, "utf8");
    const attestationEvent = ledgerText.split(/\r?\n/).filter(Boolean).map(JSON.parse)
      .find(event => event.event_type === "UNIT_ATTESTATION");
    if (attestationEvent?.source_set?.mode !== "required-source-set"
      || attestationEvent.source_set.source_count !== SOURCE_COUNT
      || Buffer.byteLength(JSON.stringify(attestationEvent)) > 2_048) {
      throw new Error("Ledger unit attestation expanded the full frozen source universe");
    }

    process.stdout.write(`${JSON.stringify({
      complete: true,
      source_count: SOURCE_COUNT,
      plan_bytes: Buffer.byteLength(JSON.stringify(plan)),
      normalized_source_id_references: plan.source_sets.reduce((sum, sourceSet) => sum + sourceSet.file_ids.length, 0),
      expanded_source_id_references_avoided: SOURCE_COUNT * (plan.checks.length - 1),
      unit_bytes: unitPage.responseBytes,
      assignment_bytes: assignment.responseBytes,
      attestation_bytes: attestation.responseBytes,
      normal_workflow_bytes: normalWorkflowBytes,
      optional_source_page_bytes: diagnosticSources.responseBytes,
      optional_interface_page_bytes: diagnosticInterfaces.responseBytes,
      attestation_event_bytes: Buffer.byteLength(JSON.stringify(attestationEvent)),
      mutation_workflow_ms: mutationWorkflowMs,
      response_limit: RESPONSE_LIMIT,
      source_list_leaked: false,
    })}\n`);
  } finally {
    if (connected) await client.close().catch(() => undefined);
    await rm(workspace, { recursive: true, force: true });
  }
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
