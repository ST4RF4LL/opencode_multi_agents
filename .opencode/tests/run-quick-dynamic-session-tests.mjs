import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { superviseQuickSession } from "../skills/vulnerability-validator-subagent/vulnerability-validation/scripts/quick-dynamic-session.mjs";
import { main } from "../skills/vulnerability-validator-subagent/vulnerability-validation/scripts/run-quick-dynamic-validation.mjs";
import { truthValidationArtifactDigest, validateTruthValidationIntake, validateQuickDynamicResultSet } from "../skills/vulnerability-validator-subagent/vulnerability-validation/scripts/truth-validation-contract.mjs";

const findingIds = ["F-001", "F-002", "F-003"];
function row(id, cleanup = "SUCCEEDED") {
  return { finding_id: id, status: "NOT_CONFIRMED", duration_ms: 0, target_origin: null, evidence_refs: [], summary: "未确认，转静态复核。", gaps: cleanup === "FAILED" ? ["测试标记未清理，需由本机操作员通过应用清理路径删除。"] : [], cleanup_status: cleanup };
}
async function simulated(delays, { dirty = false, invalid = false, exit = false } = {}) {
  let clock = 0, index = -1, phaseStart = 0, stopped = 0;
  const grants = [];
  const outcome = await superviseQuickSession({
    findings: findingIds.map(finding_id => ({ finding_id })), now: () => clock,
    publish: async phase => { index++; phaseStart = clock; grants.push(phase); },
    read: async () => clock - phaseStart >= delays[index] ? {} : null,
    accept: async (_, phase) => {
      if (invalid && index === 2) throw Error("无效阶段");
      return phase.phase === "SETUP" ? { status: "READY", summary: "共享环境就绪。" } : row(phase.finding_id, dirty && index === 1 ? "FAILED" : "SUCCEEDED");
    },
    processState: () => ({ exited: exit, code: exit ? 1 : null }),
    pause: async () => { clock += 1000; }, stop: async () => { stopped++; },
  });
  assert.equal(stopped, 1);
  return { outcome, grants };
}
const full = await simulated([239000, 179000, 178000, 177000]);
assert.equal(full.outcome.environment_setup.elapsed_ms, 239000);
assert.equal(full.outcome.results.length, 3);
assert.deepEqual(full.outcome.results.map(row => row.duration_ms), [179000, 178000, 177000]);
assert.equal(full.outcome.elapsed_ms, 773000);
assert.deepEqual(full.grants.map(phase => phase.deadline_seconds), [240, 180, 180, 180]);
assert.equal(new Set(full.grants.map(phase => phase.phase_id)).size, 4);
const timeout = await simulated([1000, 1000, Infinity]);
assert.equal(timeout.outcome.results[0].status, "NOT_CONFIRMED");
assert.equal(timeout.outcome.results[1].status, "TIMED_OUT");
assert.equal(timeout.outcome.results[1].duration_ms, 180000);
assert.equal(timeout.grants.length, 3);
assert.equal(timeout.outcome.deadline_exceeded, true);
const setupTimeout = await simulated([Infinity]);
assert.equal(setupTimeout.outcome.environment_setup.status, "TIMED_OUT");
assert.equal(setupTimeout.outcome.environment_setup.elapsed_ms, 240000);
assert.equal(setupTimeout.outcome.results.length, 0);
assert.equal((await simulated([0, 0], { dirty: true })).grants.length, 2);
assert.equal((await simulated([0, 0, 0], { invalid: true })).outcome.results[1].status, "BLOCKED");
assert.equal((await simulated([0], { exit: true })).outcome.environment_setup.status, "BLOCKED");

const root = await mkdtemp(join(tmpdir(), "quick-shared-session-"));
const savedEnvironment = { ...process.env };
try {
  const intake = {
    schema_version: 2, artifact_type: "finding-truth-validation-intake", audit_id: "quick-session-test", round: 1, scope_digest: "a".repeat(64),
    policy: { quick_dynamic: { enabled: true, explicit_task_opt_in: true, deadline_seconds: 180, setup_deadline_seconds: 240, environment_reuse: "AUDIT_ROUND", target_scope: "LOOPBACK_ONLY" }, static_review: "AFFIRMATIVE_NEGATIVE_MODERATOR", full_dynamic_trigger: "MANUAL_ONLY" },
    findings: findingIds.map(finding_id => ({ finding_id, finding_object_digest: "b".repeat(64), finding_path: "reports/findings.json", adjudication_state: "SUPPORTED_STATIC", quick_dynamic_eligible: true, runtime_request_path: null })),
  };
  intake.artifact_digest = truthValidationArtifactDigest(intake);
  assert.deepEqual(validateTruthValidationIntake(intake), []);
  await mkdir(join(root, "reports/validation"), { recursive: true });
  await writeFile(join(root, "reports/validation/intake.json"), JSON.stringify(intake));
  const context = "URL: http://127.0.0.1:4173\n无需登录的专用测试环境。\n";
  const contextPath = join(root, "private.txt");
  await writeFile(contextPath, context);
  Object.assign(process.env, { AUDIT_WORKSPACE_ROOT: root, AUDIT_QUICK_DYNAMIC_ENABLED: "true", AUDIT_TEST_ENVIRONMENT_CONTEXT_PATH: contextPath, AUDIT_TEST_ENVIRONMENT_CONTEXT_SHA256: createHash("sha256").update(context).digest("hex") });
  for (const mode of ["valid", "remote", "missing", "changed", "dirty", "bad-phase", "setup-skipped", "exit"]) {
    let starts = 0, stopped = false, workerError;
    const phases = [];
    let worker;
    const output = `reports/validation/quick/${mode}.json`;
    await main(["--intake", "reports/validation/intake.json", "--output", output], (_command, _args, env) => {
      starts++;
      worker = (async () => {
        const seen = new Set();
        while (!stopped) {
          let phase;
          try { phase = JSON.parse(await readFile(env.AUDIT_QUICK_DYNAMIC_CONTROL_PATH, "utf8")); } catch {}
          if (!phase || seen.has(phase.phase_id)) { await new Promise(resolve => setTimeout(resolve, 5)); continue; }
          seen.add(phase.phase_id); phases.push(phase);
          if (mode === "exit") return;
          let value;
          if (phase.phase === "SETUP") value = { phase_id: phase.phase_id, phase: "SETUP", status: mode === "setup-skipped" ? "SKIPPED" : "READY", summary: "测试环境状态已记录。" };
          else {
            const ref = `reports/validation/quick/evidence/${intake.audit_id}/${mode}-${phase.finding_id}.json`;
            const proof = join(root, ref);
            await mkdir(dirname(proof), { recursive: true });
            if (mode !== "missing") await writeFile(proof, "{}\n");
            if (mode === "changed" && phase.finding_id === "F-002") await writeFile(join(root, `reports/validation/quick/evidence/${intake.audit_id}/${mode}-F-001.json`), "changed\n");
            value = { phase_id: mode === "bad-phase" ? "wrong" : phase.phase_id, phase: "FINDING", result: { ...row(phase.finding_id, mode === "dirty" ? "FAILED" : "SUCCEEDED"), status: "CONFIRMED", target_origin: mode === "remote" ? "https://example.com" : "http://127.0.0.1:4173", evidence_refs: [ref] } };
          }
          await writeFile(phase.result_path, JSON.stringify(value));
        }
      })().catch(error => { workerError = error; });
      return { state: () => ({ exited: mode === "exit" || Boolean(workerError), code: 1 }), stop: async () => { stopped = true; await worker; } };
    });
    if (workerError) throw workerError;
    assert.equal(starts, 1, "all phases must share one process");
    const result = JSON.parse(await readFile(join(root, output), "utf8"));
    assert.deepEqual(validateQuickDynamicResultSet(result, intake), [], mode);
    if (mode === "valid") {
      assert.ok(result.results.every(row => row.status === "CONFIRMED"));
      assert.equal(phases.length, 4);
      assert.equal(result.evidence_bindings[0].sha256, createHash("sha256").update("{}\n").digest("hex"));
      const overBudget = structuredClone(result); overBudget.results[0].duration_ms = 180001;
      overBudget.artifact_digest = truthValidationArtifactDigest(overBudget);
      assert.ok(validateQuickDynamicResultSet(overBudget, intake).some(error => error.includes("duration-invalid")));
    } else if (mode === "dirty") {
      assert.deepEqual(result.results.map(row => row.status), ["CONFIRMED", "SKIPPED", "SKIPPED"]);
    } else if (mode === "changed") {
      assert.equal(result.results[0].status, "BLOCKED");
      assert.equal(result.results[1].status, "CONFIRMED");
    } else if (["exit", "setup-skipped"].includes(mode)) {
      assert.ok(result.results.every(row => row.status === "SKIPPED"));
    } else assert.deepEqual(result.results.map(row => row.status), ["BLOCKED", "SKIPPED", "SKIPPED"]);
  }
  for (const mode of ["disabled", "bad-digest", "remote-context", "empty-context"]) {
    const content = mode === "remote-context" ? "URL: https://example.com\n" : mode === "empty-context" ? "" : context;
    await writeFile(contextPath, content);
    process.env.AUDIT_QUICK_DYNAMIC_ENABLED = mode === "disabled" ? "false" : "true";
    process.env.AUDIT_TEST_ENVIRONMENT_CONTEXT_SHA256 = mode === "bad-digest" ? "0".repeat(64) : createHash("sha256").update(content).digest("hex");
    const output = `reports/validation/quick/${mode}.json`;
    await main(["--intake", "reports/validation/intake.json", "--output", output], () => assert.fail("invalid gate must not start a process"));
    const result = JSON.parse(await readFile(join(root, output), "utf8"));
    assert.deepEqual(validateQuickDynamicResultSet(result, intake), []);
    assert.ok(result.results.every(row => row.status === "SKIPPED"));
  }
} finally {
  for (const key of Object.keys(process.env)) if (!(key in savedEnvironment)) delete process.env[key];
  Object.assign(process.env, savedEnvironment);
  await rm(root, { recursive: true, force: true });
}
process.stdout.write(JSON.stringify({ complete: true, contract: "quick-dynamic-shared-session-v2" }) + "\n");
