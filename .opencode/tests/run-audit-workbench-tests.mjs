#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { EventEmitter, once } from "node:events";
import { PassThrough } from "node:stream";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AuditRunner } from "../web/dynamic-validation-observatory/audit-runner.mjs";
import { DynamicValidationRunner } from "../web/dynamic-validation-observatory/validation-runner.mjs";
import { buildWorkspaceSnapshot } from "../web/dynamic-validation-observatory/workspace-model.mjs";
import { createAuditWorkbenchServer, parseArgs } from "../web/dynamic-validation-observatory/server.mjs";
import { buildWebXssInputEnvelope, buildWebXssRuntimeRequest } from "./fixtures/web-xss-runtime-fixture.mjs";

const OPENCODE = resolve(dirname(fileURLToPath(import.meta.url)), "..");

class FakeChild extends EventEmitter {
  constructor() {
    super();
    this.pid = 4242;
    this.stdout = new PassThrough();
    this.stderr = new PassThrough();
    this.signals = [];
  }

  kill(signal) {
    this.signals.push(signal);
    if (signal === "SIGTERM") queueMicrotask(() => this.emit("close", null, signal));
    return true;
  }
}

const temp = await mkdtemp(join(tmpdir(), "audit-workbench-"));
const repositoryRoot = join(temp, "repository");
const reportsRoot = join(repositoryRoot, "reports");
const stateRoot = join(temp, "state");
const runtimeRoot = join(reportsRoot, "validation-handoff", "runtime");

try {
  await mkdir(join(repositoryRoot, ".opencode"), { recursive: true });
  await mkdir(join(reportsRoot, "coverage"), { recursive: true });
  await mkdir(join(reportsRoot, "correlation"), { recursive: true });
  await mkdir(join(reportsRoot, "final"), { recursive: true });
  await mkdir(runtimeRoot, { recursive: true });
  await writeFile(join(repositoryRoot, ".opencode", "opencode.json"), "{}\n", "utf8");
  await writeFile(join(repositoryRoot, "README.md"), "fixture\n", "utf8");
  await writeFile(join(reportsRoot, "coverage", "coverage-plan.audit-history.json"), JSON.stringify({
    audit_id: "audit-history",
    complete: true,
    summary: { required: 3 },
  }), "utf8");
  await writeFile(join(reportsRoot, "correlation", "correlation.audit-history.json"), JSON.stringify({
    audit_id: "audit-history",
    canonical_findings: [{ canonical_id: "F-001", title: "越权读取测试记录", severity: "HIGH", dimension: "D1", locations: [{ path: "src/api.js", line: 12 }] }],
  }), "utf8");
  await writeFile(join(reportsRoot, "final", "security-audit-report.audit-history.md"), "# 安全审计报告\n", "utf8");

  execFileSync("git", ["init", "-q", repositoryRoot]);
  execFileSync("git", ["-C", repositoryRoot, "config", "user.name", "Audit Test"]);
  execFileSync("git", ["-C", repositoryRoot, "config", "user.email", "audit-test@example.invalid"]);
  execFileSync("git", ["-C", repositoryRoot, "add", "."]);
  execFileSync("git", ["-C", repositoryRoot, "commit", "-qm", "fixture"]);
  const fixtureCommit = execFileSync("git", ["-C", repositoryRoot, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();

  const validationAuditRoot = join(runtimeRoot, "web-xss-fixture");
  await mkdir(validationAuditRoot, { recursive: true });
  const validationRequest = buildWebXssRuntimeRequest(fixtureCommit);
  const requestPath = join(validationAuditRoot, "request.json");
  const requestBytes = `${JSON.stringify(validationRequest, null, 2)}\n`;
  await writeFile(requestPath, requestBytes, "utf8");
  const validationEnvelope = buildWebXssInputEnvelope({ request: validationRequest, requestPath, requestBytes });
  await writeFile(join(validationAuditRoot, "envelope-input.json"), `${JSON.stringify(validationEnvelope, null, 2)}\n`, "utf8");

  const snapshot = await buildWorkspaceSnapshot({ reportsRoot });
  assert.equal(snapshot.summary.audit_count, 2);
  assert.equal(snapshot.summary.finding_count, 1);
  assert.equal(snapshot.summary.report_count, 1);
  assert.match(snapshot.reports[0].sha256, /^[a-f0-9]{64}$/);
  assert.equal(snapshot.audits.find(audit => audit.id === "audit-history").progress, 100);
  assert.equal(snapshot.findings[0].id, "F-001");

  let spawnCall = null;
  const child = new FakeChild();
  const dynamicChild = new FakeChild();
  let dynamicSpawnCall = null;
  const runner = new AuditRunner({
    stateRoot,
    repositories: [{ id: "fixture", name: "测试仓库", path: repositoryRoot }],
    enabled: true,
    spawnProcess(command, args, options) {
      spawnCall = { command, args, options };
      return child;
    },
  });
  await runner.ready;
  const dynamicStateRoot = join(temp, "dynamic-state");
  const dynamicRunner = new DynamicValidationRunner({
    stateRoot: dynamicStateRoot,
    enabled: true,
    registryPath: join(OPENCODE, "skills/common-subagent/audit-artifact-management/contracts/stage-agent-contracts.json"),
    rolesPath: join(OPENCODE, "agent-manifest/roles.json"),
    authSourceRoot: join(temp, "empty-opencode-auth"),
    resultValidator: async () => {},
    spawnProcess(command, args, options) {
      dynamicSpawnCall = { command, args, options };
      return dynamicChild;
    },
  });
  const repositories = await runner.listRepositories();
  assert.equal(repositories[0].configured, true);
  assert.equal(repositories[0].git_repository, true);
  assert.equal(JSON.stringify(repositories).includes(repositoryRoot), false);

  const server = createAuditWorkbenchServer({ runtimeRoot, runner, dynamicRunner });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const workspaceResponse = await fetch(`${base}/api/v1/workspace`);
    assert.equal(workspaceResponse.status, 200);
    const workspace = await workspaceResponse.json();
    assert.equal(workspace.summary.finding_count, 1);
    assert.equal(workspace.audits[0].repository_id, "fixture");

    const createResponse = await fetch(`${base}/api/v1/audits`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "request-001" },
      body: JSON.stringify({
        audit_id: "audit-live-001",
        name: "发布前安全审计; touch /tmp/never",
        repository_id: "fixture",
        ref: "HEAD",
        allow_dirty: true,
      }),
    });
    assert.equal(createResponse.status, 202);
    const created = await createResponse.json();
    assert.equal(created.id, "audit-live-001");
    assert.equal(created.idempotency_digest, undefined);

    for (let attempt = 0; attempt < 20 && runner.getAudit(created.id)?.status !== "running"; attempt += 1) await new Promise(resolve => setImmediate(resolve));
    assert.equal(runner.getAudit(created.id).status, "running");
    assert.equal(spawnCall.command, "opencode");
    assert.equal(spawnCall.options.shell, false);
    assert.equal(spawnCall.options.cwd, repositoryRoot);
    assert.deepEqual(spawnCall.args.slice(0, 7), ["run", "--format", "json", "--agent", "security-audit-orchestrator", "--dir", repositoryRoot]);
    assert.match(spawnCall.args.at(-1), /audit-live-001/);
    assert.match(spawnCall.args.at(-1), /不得自行启动动态验证/);

    child.stdout.write('{"type":"agent.progress","token":"must-not-leak"}\n');
    for (let attempt = 0; attempt < 20 && (await runner.eventsSince(created.id)).length < 4; attempt += 1) await new Promise(resolve => setImmediate(resolve));
    const events = await runner.eventsSince(created.id);
    assert.equal(events.some(event => JSON.stringify(event).includes("must-not-leak")), false);
    assert.deepEqual(events.map(event => event.sequence), events.map((_, index) => index + 1));
    const logResponse = await fetch(`${base}/api/v1/audits/${created.id}/logs?limit=20`);
    assert.equal(logResponse.status, 200);
    assert.equal(JSON.stringify(await logResponse.json()).includes("must-not-leak"), false);

    const duplicateResponse = await fetch(`${base}/api/v1/audits`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "request-001" },
      body: JSON.stringify({ audit_id: "audit-other-id", repository_id: "fixture", ref: "HEAD" }),
    });
    assert.equal(duplicateResponse.status, 202);
    assert.equal((await duplicateResponse.json()).id, "audit-live-001");

    const requestListResponse = await fetch(`${base}/api/v1/validation-requests`);
    assert.equal(requestListResponse.status, 200);
    const requestList = await requestListResponse.json();
    assert.equal(requestList.count, 1);
    assert.equal(requestList.items[0].dispatch_ready, true);

    const remoteValidationResponse = await fetch(`${base}/api/v1/validations`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "dynamic-remote" },
      body: JSON.stringify({
        validation_request_id: "web-xss-fixture::FIND-WEB-XSS-001",
        repository_id: "fixture",
        target_base_url: "https://example.com",
        attacker_account: { username: "attacker", password: "secret-a" },
        victim_account: { username: "victim", password: "secret-b" },
        login_instructions: "测试登录。",
        cleanup_instructions: "删除测试数据。",
        explicit_authorization: true,
        test_environment: true,
      }),
    });
    assert.equal(remoteValidationResponse.status, 422);
    assert.equal(dynamicSpawnCall, null);

    const validationResponse = await fetch(`${base}/api/v1/validations`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "dynamic-001" },
      body: JSON.stringify({
        validation_request_id: "web-xss-fixture::FIND-WEB-XSS-001",
        repository_id: "fixture",
        target_base_url: "http://127.0.0.1:8080/profile",
        attacker_account: { username: "attacker-fixture", password: "attacker-secret-value" },
        victim_account: { username: "victim-fixture", password: "victim-secret-value" },
        login_instructions: "通过测试登录页输入账号密码并确认进入 profile 页面。",
        cleanup_instructions: "通过 profile 页面清空测试 display name 并刷新确认。",
        explicit_authorization: true,
        test_environment: true,
      }),
    });
    assert.equal(validationResponse.status, 202);
    assert.equal((await validationResponse.clone().json()).idempotency_digest, undefined);
    for (let attempt = 0; attempt < 100 && dynamicRunner.getRun("web-xss-fixture::FIND-WEB-XSS-001")?.status !== "running"; attempt += 1) await new Promise(resolve => setTimeout(resolve, 2));
    assert.equal(dynamicRunner.getRun("web-xss-fixture::FIND-WEB-XSS-001").status, "running");
    assert.equal(dynamicSpawnCall.command, "opencode");
    assert.equal(dynamicSpawnCall.options.shell, false);
    assert.equal(dynamicSpawnCall.args[4], "dynamic-vulnerability-validator");
    assert.notEqual(dynamicSpawnCall.options.env.XDG_DATA_HOME, process.env.XDG_DATA_HOME);
    assert.equal(JSON.stringify(dynamicSpawnCall.args).includes("attacker-secret-value"), false);
    assert.equal(JSON.stringify(dynamicSpawnCall.args).includes("victim-secret-value"), false);
    const authorizationFile = dynamicSpawnCall.args[dynamicSpawnCall.args.indexOf("--file") + 1];
    assert.match(await readFile(authorizationFile, "utf8"), /attacker-secret-value/);
    assert.equal((await stat(authorizationFile)).mode & 0o077, 0);
    dynamicChild.stdout.write('{"password":"attacker-secret-value","token":"victim-secret-value"}\n');
    await writeFile(join(validationAuditRoot, "FIND-WEB-XSS-001.result.json"), "{}\n", "utf8");
    dynamicChild.emit("close", 0, null);
    for (let attempt = 0; attempt < 60 && dynamicRunner.getRun("web-xss-fixture::FIND-WEB-XSS-001")?.ephemeral_cleanup !== "SUCCEEDED"; attempt += 1) await new Promise(resolve => setImmediate(resolve));
    assert.equal(dynamicRunner.getRun("web-xss-fixture::FIND-WEB-XSS-001").status, "completed");
    assert.equal(dynamicRunner.getRun("web-xss-fixture::FIND-WEB-XSS-001").ephemeral_cleanup, "SUCCEEDED");
    assert.equal(dynamicRunner.getRun("web-xss-fixture::FIND-WEB-XSS-001").result_validation, "PASSED");
    const dynamicLog = await readFile(join(dynamicRunner.directory("web-xss-fixture::FIND-WEB-XSS-001"), "runner.log.jsonl"), "utf8");
    assert.equal(dynamicLog.includes("attacker-secret-value"), false);
    assert.equal(dynamicLog.includes("victim-secret-value"), false);
    await assert.rejects(stat(resolve(dynamicSpawnCall.options.env.XDG_DATA_HOME, "..")), error => error.code === "ENOENT");

    const crossOriginResponse = await fetch(`${base}/api/v1/audits`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "cross-origin", Origin: "https://attacker.invalid" },
      body: JSON.stringify({ audit_id: "audit-cross-origin", repository_id: "fixture", ref: "HEAD" }),
    });
    assert.equal(crossOriginResponse.status, 403);

    const running = runner.getAudit(created.id);
    const pauseResponse = await fetch(`${base}/api/v1/audits/${created.id}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": `"${running.version}"`, "Idempotency-Key": "pause-001" },
      body: JSON.stringify({ action: "pause" }),
    });
    assert.equal(pauseResponse.status, 202);
    assert.equal(child.signals.at(-1), "SIGSTOP");

    const paused = runner.getAudit(created.id);
    const resumeResponse = await fetch(`${base}/api/v1/audits/${created.id}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": `"${paused.version}"`, "Idempotency-Key": "resume-001" },
      body: JSON.stringify({ action: "resume" }),
    });
    assert.equal(resumeResponse.status, 202);
    assert.equal(child.signals.at(-1), "SIGCONT");

    const indexResponse = await fetch(`${base}/`);
    assert.equal(indexResponse.status, 200);
    assert.match(await indexResponse.text(), /OpenCode 安全审计工作台/);
  } finally {
    server.close();
    await once(server, "close");
  }

  assert.throws(() => parseArgs(["--host", "0.0.0.0"]), /loopback/);
  assert.throws(() => parseArgs(["--repo", "bad-format"]), /id=\/absolute\/path/);
  const options = parseArgs(["--enable-runner", "--enable-dynamic-validation", "--repo", `fixture=${repositoryRoot}`, "--port", "0"]);
  assert.equal(options.runnerEnabled, true);
  assert.equal(options.dynamicRunnerEnabled, true);
  assert.equal(options.repositories[0].id, "fixture");

  const orphanSession = await mkdtemp(join(tmpdir(), "opencode-dynval-"));
  const recoveryState = join(temp, "recovery-state");
  const recoveryId = "recovery::FIND-WEB-XSS-002";
  const recoveryDirectory = join(recoveryState, createHash("sha256").update(recoveryId).digest("hex").slice(0, 32));
  await mkdir(recoveryDirectory, { recursive: true });
  await writeFile(join(recoveryDirectory, "run.json"), `${JSON.stringify({
    id: recoveryId,
    audit_id: "recovery",
    finding_id: "FIND-WEB-XSS-002",
    repository_id: "fixture",
    status: "running",
    version: 2,
    event_sequence: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ephemeral_cleanup: "PENDING",
    ephemeral_session_root: orphanSession,
  })}\n`, "utf8");
  const recoveredRunner = new DynamicValidationRunner({
    stateRoot: recoveryState,
    registryPath: join(OPENCODE, "skills/common-subagent/audit-artifact-management/contracts/stage-agent-contracts.json"),
    rolesPath: join(OPENCODE, "agent-manifest/roles.json"),
    authSourceRoot: join(temp, "empty-opencode-auth"),
  });
  await recoveredRunner.ready;
  assert.equal(recoveredRunner.getRun(recoveryId).status, "failed");
  assert.equal(recoveredRunner.getRun(recoveryId).ephemeral_cleanup, "SUCCEEDED");
  await assert.rejects(stat(orphanSession), error => error.code === "ENOENT");

  process.stdout.write(`${JSON.stringify({ complete: true, service: "opencode-audit-workbench", cases: 54 })}\n`);
} finally {
  await rm(temp, { recursive: true, force: true });
}
