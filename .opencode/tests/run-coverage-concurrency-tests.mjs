#!/usr/bin/env node

import { spawn } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  COVERAGE_MODEL_VERSION,
  PLAN_SCHEMA_VERSION,
  coverageCheckId,
  objectDigest,
  sha256,
  sourceSetId,
  validatePlan,
} from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-v2-common.mjs";
import {
  initializeLedger,
  inspectSubject,
  loadPlan,
  readLedger,
  verifyLedger,
} from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-ledger-core.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const AUDIT_ID = "coverage-concurrency-fixture";
const LENSES = ["sink-driven", "control-driven", "config-driven"];

function makePlan() {
  const fileId = `file:${sha256("concurrency-source").slice(0, 24)}`;
  const sourceSet = {
    source_set_id: sourceSetId([fileId]),
    file_ids: [fileId],
  };
  const checks = LENSES.map(lens => ({
    check_id: coverageCheckId("catalog-domain", "domain:web", "JW-TEST-LOCK", "web", lens),
    subject_kind: "catalog-domain",
    subject_id: "domain:web",
    vulnerability_type_id: "JW-TEST-LOCK",
    domain: "web",
    lens,
    focus_area_id: "FA-CONCURRENCY",
    dimensions: ["D1"],
    applicability: "REQUIRED",
    applicability_reason: "concurrency-regression",
    negative_discovery_required: true,
    required_source_set_id: sourceSet.source_set_id,
    required_source_count: 1,
    evidence_contract: {
      question_field: `${lens.replace("-driven", "")}_question`,
      question: "Was the concurrent fixture reviewed?",
      required_receipt_fields: ["source_set_id", "locators", "query_or_rule", "tool", "result_attestation"],
    },
  }));
  const plan = {
    schema_version: PLAN_SCHEMA_VERSION,
    coverage_model_version: COVERAGE_MODEL_VERSION,
    audit_id: AUDIT_ID,
    catalog_profile_id: "concurrency-v4",
    scope_digest: sha256("concurrency-scope"),
    required_lenses: LENSES,
    inputs: { snapshot_digest: sha256("concurrency-snapshot") },
    source_index: [{
      file_id: fileId,
      path: "src/concurrency.js",
      type: "file",
      sha256: sha256("concurrency-source"),
      link_target: null,
      owner_agent: "web-source-auditor",
    }],
    source_sets: [sourceSet],
    universes: {
      files: 1,
      function_files: 0,
      functions: 0,
      interfaces: 0,
      interface_anchors: 0,
      vulnerability_types: 1,
      active_domains: ["web"],
    },
    inventory: {
      eligible_files: 1,
      resolved_files: 1,
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
    claim_boundary: "Concurrency fixture.",
  };
  plan.manifest_digest = objectDigest(plan);
  const errors = validatePlan(plan);
  if (errors.length > 0) throw new Error(`Concurrency plan is invalid: ${errors.join("; ")}`);
  return plan;
}

async function worker() {
  const [, , , planPath, ledgerPath, checkId, workerId] = process.argv;
  await initializeLedger({ planPath, ledgerPath });
  await inspectSubject({
    planPath,
    ledgerPath,
    checkId,
    sessionId: `worker-session-${workerId}`,
    agentName: "web-source-auditor",
    idempotencyKey: `worker-inspect-${workerId}`,
  });
}

async function reader() {
  const [, , , ledgerPath] = process.argv;
  for (let index = 0; index < 100; index += 1) {
    const events = await readLedger(ledgerPath, { allowMissing: true });
    if (events.some((event, eventIndex) => event.sequence !== eventIndex)) {
      throw new Error("Concurrent reader observed a discontinuous ledger");
    }
    await new Promise(resolveWait => setTimeout(resolveWait, 1));
  }
}

function spawnChild(args, label) {
  return new Promise((resolveWorker, rejectWorker) => {
    const child = spawn(process.execPath, [SELF, ...args], {
      cwd: resolve(HERE, "../.."),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", chunk => stdout.push(chunk));
    child.stderr.on("data", chunk => stderr.push(chunk));
    child.on("error", rejectWorker);
    child.on("close", status => {
      if (status === 0) resolveWorker();
      else rejectWorker(new Error(`${label} failed (${status})\n${Buffer.concat(stderr)}\n${Buffer.concat(stdout)}`));
    });
  });
}

function spawnWorker(planPath, ledgerPath, checkId, workerId) {
  return spawnChild(["worker", planPath, ledgerPath, checkId, workerId], `Coverage worker ${workerId}`);
}

async function main() {
  const workspace = await mkdtemp(join(tmpdir(), "opencode-coverage-concurrency-"));
  try {
    const plan = makePlan();
    const planPath = join(workspace, "coverage-plan.json");
    const ledgerPath = join(workspace, "ledger", "coverage-ledger.jsonl");
    await mkdir(dirname(ledgerPath), { recursive: true });
    await writeFile(planPath, `${JSON.stringify(plan, null, 2)}\n`, "utf8");
    await Promise.all([
      ...plan.checks.map((check, index) => spawnWorker(planPath, ledgerPath, check.check_id, index)),
      spawnChild(["reader", ledgerPath], "Coverage concurrent reader"),
    ]);

    const loadedFirst = await loadPlan(planPath);
    const loadedSecond = await loadPlan(planPath);
    const [events, verification] = await Promise.all([
      readLedger(ledgerPath),
      verifyLedger({ planPath, ledgerPath, requireFinalized: false }),
    ]);
    const genesis = events.filter(event => event.event_type === "GENESIS");
    const inspections = events.filter(event => event.event_type === "INSPECT");
    if (loadedFirst !== loadedSecond) throw new Error("Immutable plan cache did not return the cached object");
    if (genesis.length !== 1 || inspections.length !== plan.checks.length) {
      throw new Error(`Concurrent mutations produced an invalid event set: genesis=${genesis.length}, inspections=${inspections.length}`);
    }
    if (events.some((event, index) => event.sequence !== index) || verification.events.length !== events.length) {
      throw new Error("Concurrent ledger sequence or verification mismatch");
    }
    process.stdout.write(`${JSON.stringify({
      complete: true,
      processes: plan.checks.length,
      events: events.length,
      genesis: genesis.length,
      inspections: inspections.length,
      concurrent_readers: 1,
      hmac_chain_verified: true,
      plan_cache_reused: true,
    })}\n`);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

if (process.argv[2] === "worker") {
  worker().catch(error => {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
} else if (process.argv[2] === "reader") {
  reader().catch(error => {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
} else {
  main().catch(error => {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
}
