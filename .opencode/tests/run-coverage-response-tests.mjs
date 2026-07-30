#!/usr/bin/env node

import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { Client } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js";
import { StdioClientTransport } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js";
import {
  COVERAGE_MODEL_VERSION,
  PLAN_SCHEMA_VERSION,
  coverageCheckId,
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
  const frozenSourceSetId = sourceSetId(sourceIds);
  const checks = LENSES.map(lens => ({
    check_id: coverageCheckId("catalog-domain", "domain:web", "JW-TEST-01", "web", lens),
    subject_kind: "catalog-domain",
    subject_id: "domain:web",
    vulnerability_type_id: "JW-TEST-01",
    domain: "web",
    lens,
    focus_area_id: "FA-LARGE",
    dimensions: ["D1"],
    applicability: "REQUIRED",
    applicability_reason: "large-source-response-regression",
    negative_discovery_required: true,
    required_source_set_id: frozenSourceSetId,
    required_source_count: sourceIds.length,
    required_interface_ids: [],
    required_catalog_ids: ["JW-TEST-01"],
    evidence_contract: {
      question_field: `${lens.replace("-driven", "")}_question`,
      question: "Was the complete frozen source universe reviewed?",
      required_receipt_fields: ["source_set_id", "locators", "query_or_rule", "tool", "result_attestation"],
    },
  }));
  const plan = {
    schema_version: PLAN_SCHEMA_VERSION,
    coverage_model_version: COVERAGE_MODEL_VERSION,
    audit_id: AUDIT_ID,
    catalog_profile_id: "response-fixture-v4",
    scope_digest: sha256("large-response-scope"),
    required_lenses: LENSES,
    inputs: { snapshot_digest: sha256("large-response-snapshot") },
    source_index: sourceIndex,
    source_sets: [{ source_set_id: frozenSourceSetId, file_ids: sourceIds }],
    universes: {
      files: SOURCE_COUNT,
      function_files: 0,
      functions: 0,
      interfaces: 0,
      interface_anchors: 0,
      vulnerability_types: 1,
      active_domains: ["web"],
    },
    inventory: {
      eligible_files: SOURCE_COUNT,
      resolved_files: SOURCE_COUNT,
      gap_files: 0,
      gap_file_ids: [],
      confirmed_interfaces: 0,
      candidate_interfaces: 0,
      candidate_interface_ids: [],
      rejected_interfaces: 0,
      unresolved_interfaces: 0,
      extractor_complete: true,
      bounded: true,
    },
    checks,
    summary: {
      atomic_checks: checks.length,
      required: checks.length,
      not_applicable: 0,
      unknown: 0,
      catalog_domain_required: checks.length,
      interface_required: 0,
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

    const packet = await call("coverage_get_packet", {
      audit_id: AUDIT_ID,
      limit: 10,
    });
    const check = packet.value.packets[0];
    if (packet.text.includes(plan.source_index[0].file_id)
      || check.required_source_count !== SOURCE_COUNT
      || check.receipt_source_scope !== "required") {
      throw new Error("Packet response leaked the frozen source list or omitted the required source-set contract");
    }

    const mutationStarted = performance.now();
    const inspection = await call("coverage_inspect_subject", {
      audit_id: AUDIT_ID,
      check_id: check.check_id,
      session_id: "large-response-session",
      agent_name: "web-source-auditor",
      idempotency_key: "large-response-inspect",
    });
    if ("source_page" in inspection.value || inspection.text.includes(plan.source_index[0].file_id)) {
      throw new Error("Subject inspection leaked source metadata into the normal workflow");
    }

    const receipt = await call("coverage_record_tool_result", {
      audit_id: AUDIT_ID,
      check_id: check.check_id,
      session_id: "large-response-session",
      assignment_token: inspection.value.assignment_token,
      idempotency_key: "large-response-receipt",
      source_scope: "required",
      locators: [{
        kind: "required-source-set",
        check_id: check.check_id,
        source_set_id: check.required_source_set_id,
        source_count: SOURCE_COUNT,
      }],
      query_or_rule: "large-response-regression",
      tool: "fixture",
      tool_version: "1.0.0",
      result_payload: "large-response-result",
      result_digest: sha256("large-response-result"),
      result_summary: "Complete frozen source set reviewed.",
    });
    if (receipt.value.receipt.source_scope !== "required"
      || receipt.value.receipt.source_count !== SOURCE_COUNT
      || !/^[a-f0-9]{64}$/.test(receipt.value.receipt.source_set_sha256 ?? "")) {
      throw new Error("Receipt response lacks the compact digest-bound source-set proof");
    }

    const decision = await call("coverage_submit_decision", {
      audit_id: AUDIT_ID,
      check_id: check.check_id,
      session_id: "large-response-session",
      assignment_token: inspection.value.assignment_token,
      idempotency_key: "large-response-decision",
      execution_state: "VERIFIED",
      result_state: "NO_FINDING",
      receipt_ids: [receipt.value.receipt.receipt_id],
      rationale: "Digest-bound complete source set reviewed.",
    });
    const mutationWorkflowMs = Number((performance.now() - mutationStarted).toFixed(2));

    const diagnosticSources = await call("coverage_get_subject_sources", {
      audit_id: AUDIT_ID,
      check_id: check.check_id,
      limit: 25,
    });
    if (diagnosticSources.value.returned !== 25 || diagnosticSources.value.total_sources !== SOURCE_COUNT) {
      throw new Error("Targeted source diagnostics did not remain cursor-paginated");
    }

    const normalWorkflowBytes = packet.responseBytes
      + inspection.responseBytes
      + receipt.responseBytes
      + decision.responseBytes;
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
    const receiptEvent = ledgerText.split(/\r?\n/).filter(Boolean).map(JSON.parse)
      .find(event => event.event_type === "RECEIPT");
    if (receiptEvent?.source_set?.mode !== "required-source-set"
      || receiptEvent.source_set.source_count !== SOURCE_COUNT
      || Buffer.byteLength(JSON.stringify(receiptEvent)) > 2_048) {
      throw new Error("Ledger receipt expanded the full frozen source universe");
    }

    process.stdout.write(`${JSON.stringify({
      complete: true,
      source_count: SOURCE_COUNT,
      plan_bytes: Buffer.byteLength(JSON.stringify(plan)),
      normalized_source_id_references: plan.source_sets.reduce((sum, sourceSet) => sum + sourceSet.file_ids.length, 0),
      expanded_source_id_references_avoided: SOURCE_COUNT * (plan.checks.length - 1),
      packet_bytes: packet.responseBytes,
      inspection_bytes: inspection.responseBytes,
      receipt_bytes: receipt.responseBytes,
      decision_bytes: decision.responseBytes,
      normal_workflow_bytes: normalWorkflowBytes,
      optional_source_page_bytes: diagnosticSources.responseBytes,
      receipt_event_bytes: Buffer.byteLength(JSON.stringify(receiptEvent)),
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
