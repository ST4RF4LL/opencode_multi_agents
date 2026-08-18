#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { EventEmitter, once } from "node:events";
import { PassThrough } from "node:stream";
import { execFile, execFileSync } from "node:child_process";
import { createServer as createHttpServer } from "node:http";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { AuditRunner } from "../web/dynamic-validation-observatory/audit-runner.mjs";
import { DynamicValidationRunner } from "../web/dynamic-validation-observatory/validation-runner.mjs";
import { EnvironmentHealthService } from "../web/dynamic-validation-observatory/environment-health.mjs";
import { OpenCodeTmuxMonitor } from "../web/dynamic-validation-observatory/tmux-monitor.mjs";
import { FindingWorkflowStore } from "../web/dynamic-validation-observatory/finding-workflow.mjs";
import { buildWorkspaceSnapshot, findingsFromArtifacts, materializeFinalReportFromModel } from "../web/dynamic-validation-observatory/workspace-model.mjs";
import { createAuditWorkbenchServer, parseArgs } from "../web/dynamic-validation-observatory/server.mjs";
import { finalReportModelDigest, renderFinalReport } from "../skills/common-subagent/audit-coverage-accounting/scripts/final-report-model-core.mjs";
import { buildWebXssInputEnvelope, buildWebXssRuntimeRequest } from "./fixtures/web-xss-runtime-fixture.mjs";

const OPENCODE = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const execFileAsync = promisify(execFile);

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

class FakeTerminalMonitor {
  constructor() {
    this.signals = [];
    this.abortCalls = [];
    this.stopCalls = 0;
    this.starts = [];
    this.resizeCalls = [];
    this.output = "OpenCode TUI fixture\nsecurity-audit-orchestrator is running";
  }

  async probe() {
    return { available: true, tmux_version: "tmux 3.test", message: "ready" };
  }

  async start({ audit, repository, environment, executionDirectory, providerSessionId = null, args }) {
    this.starts.push({ audit_id: audit.id, repository, environment, executionDirectory, providerSessionId, args });
    return {
      backend: "tmux",
      transport: "opencode-run+terminal-multiplexer",
      supported: true,
      status: "ready",
      live: true,
      socket_name: "owa-0123456789abcdef",
      target: "audit:tui",
      provider_session_id: providerSessionId ?? `ses_${audit.id}`,
      relay_spec_path: join(temp, `${audit.id}-terminal-output-relay.json`),
      attach_command: "tmux -L owa-0123456789abcdef attach-session -r -t audit:tui",
      message: "fixture terminal ready",
    };
  }

  async capture() {
    return this.output;
  }

  async targetLive() {
    return true;
  }

  async resize(terminal, columns, rows) {
    this.resizeCalls.push({ terminal, columns, rows });
    return { columns, rows };
  }

  async signalRun(_terminal, signal) {
    this.signals.push(signal);
  }

  async abort(terminal, directory) {
    this.abortCalls.push({ terminal, directory });
    return true;
  }

  async stop() {
    this.stopCalls += 1;
  }
}

const temp = await mkdtemp(join(tmpdir(), "audit-workbench-"));
const repositoryRoot = join(temp, "repository");
const operatorSelectedRoot = join(temp, "operator-selected-project");
const platformRoot = join(temp, "platform");
const reportsRoot = join(platformRoot, "reports", "repositories", "fixture");
const stateRoot = join(platformRoot, "reports", "platform", "audit-runs");
const runtimeRoot = join(reportsRoot, "validation-handoff", "runtime");

function finalReportModel(auditId) {
  const model = {
    schema_version: 1,
    audit_id: auditId,
    scope_digest: "a".repeat(64),
    report_kind: "FINAL",
    coverage: {
      summary_digest: "b".repeat(64),
      coverage_status: "COMPLETE",
      seal_state: "FINALIZED_COMPLETE",
      policy_mode: "assurance",
      policy_satisfied: true,
      metrics: [],
    },
    inputs: {
      coverage_summary: "reports/coverage/summary.json",
      adjudication_input: "reports/adjudication/input.json",
      adjudication: "reports/adjudication/decision.json",
      truth_validation_intake: "reports/validation/intake.json",
      quick_dynamic_results: "reports/validation/quick.json",
      affirmative_review: "reports/validation/affirmative.json",
      negative_review: "reports/validation/negative.json",
      moderator_review: "reports/validation/moderator.json",
      validation_routing: "reports/validation/routing.json",
      cvss_assessment: "reports/adjudication/cvss.json",
      attack_chains: "reports/attack-chains/chains.json",
    },
    truth_validation: {
      routing_digest: "c".repeat(64),
      full_dynamic_trigger: "MANUAL_ONLY",
      summary: { total: 0, true_positive: 0, false_positive: 0, inconclusive: 0 },
      source: {
        artifact: "reports/validation/routing.json",
        digest: "c".repeat(64),
        json_pointer: "/summary",
      },
    },
    findings: [],
    excluded_findings: [],
    chains: [],
    rejected_chains: [],
  };
  model.manifest_digest = finalReportModelDigest(model);
  return model;
}

try {
  await mkdir(join(repositoryRoot, ".opencode"), { recursive: true });
  await mkdir(operatorSelectedRoot, { recursive: true });
  await mkdir(join(reportsRoot, "coverage"), { recursive: true });
  await mkdir(join(reportsRoot, "correlation"), { recursive: true });
  await mkdir(join(reportsRoot, "final"), { recursive: true });
  await mkdir(join(reportsRoot, "stage-deliveries", "audit-history", "sets"), { recursive: true });
  await mkdir(runtimeRoot, { recursive: true });
  await writeFile(join(repositoryRoot, ".opencode", "opencode.json"), "{}\n", "utf8");
  await writeFile(join(repositoryRoot, "README.md"), "fixture\n", "utf8");
  await writeFile(join(operatorSelectedRoot, "README.md"), "operator selected fixture\n", "utf8");
  await writeFile(join(reportsRoot, "coverage", "coverage-plan.audit-history.json"), JSON.stringify({
    audit_id: "audit-history",
    complete: true,
    summary: { required: 3 },
  }), "utf8");
  await writeFile(join(reportsRoot, "correlation", "correlation.audit-history.json"), JSON.stringify({
    audit_id: "audit-history",
    canonical_findings: [{
      canonical_id: "F-001",
      title: "越权读取测试记录",
      description: "服务未校验记录归属。",
      severity: "HIGH",
      dimension: "D1",
      locations: [{ path: "src/api.js", line: 12, detail: "缺少 ownership guard" }],
      remediation: "按当前主体校验记录所有权。",
      residual_uncertainty: ["运行时路由部署状态未确认。"],
      source_findings: [{ finding_id: "SOURCE-001" }],
      contradictions: [],
    }],
  }), "utf8");
  await writeFile(join(reportsRoot, "final", "security-audit-report.audit-history.md"), "# 安全审计报告\n\n| 项目 | 状态 |\n|---|---|\n| 边界 | 通过 |\n\n<script>alert('blocked')</script>\n\n[危险链接](javascript:alert('blocked'))\n", "utf8");
  await writeFile(join(reportsRoot, "stage-deliveries", "audit-history", "sets", "runtime-validation-requests.r1.json"), JSON.stringify({
    schema_version: 1,
    audit_id: "audit-history",
    requests: [],
  }), "utf8");
  const verifiedModel = finalReportModel("audit-sealed");
  await writeFile(join(reportsRoot, "final", "security-audit-report-model.audit-sealed.json"), `${JSON.stringify(verifiedModel, null, 2)}\n`, "utf8");
  await writeFile(join(reportsRoot, "final", "security-audit-report.audit-sealed.md"), renderFinalReport(verifiedModel), "utf8");
  const mismatchedModel = finalReportModel("audit-mismatch");
  await writeFile(join(reportsRoot, "final", "security-audit-report-model.audit-mismatch.json"), `${JSON.stringify(mismatchedModel, null, 2)}\n`, "utf8");
  await writeFile(join(reportsRoot, "final", "security-audit-report.audit-mismatch.md"), `${renderFinalReport(mismatchedModel)}手工篡改\n`, "utf8");

  execFileSync("git", ["init", "-q", repositoryRoot]);
  execFileSync("git", ["-C", repositoryRoot, "config", "user.name", "Audit Test"]);
  execFileSync("git", ["-C", repositoryRoot, "config", "user.email", "audit-test@example.invalid"]);
  execFileSync("git", ["-C", repositoryRoot, "add", "."]);
  execFileSync("git", ["-C", repositoryRoot, "commit", "-qm", "fixture"]);
  execFileSync("git", ["init", "-q", operatorSelectedRoot]);
  execFileSync("git", ["-C", operatorSelectedRoot, "config", "user.name", "Audit Test"]);
  execFileSync("git", ["-C", operatorSelectedRoot, "config", "user.email", "audit-test@example.invalid"]);
  execFileSync("git", ["-C", operatorSelectedRoot, "add", "."]);
  execFileSync("git", ["-C", operatorSelectedRoot, "commit", "-qm", "fixture"]);
  const canonicalRepositoryRoot = await realpath(repositoryRoot);
  const canonicalOperatorSelectedRoot = await realpath(operatorSelectedRoot);
  const fixtureCommit = execFileSync("git", ["-C", repositoryRoot, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();

  let tmuxInstalled = true;
  try { execFileSync("tmux", ["-V"], { stdio: "ignore" }); } catch { tmuxInstalled = false; }
  if (tmuxInstalled) {
    const fakeOpenCode = join(temp, "fake-opencode.mjs");
    await writeFile(fakeOpenCode, `#!/usr/bin/env node
import { createServer } from "node:http";
const [mode, ...args] = process.argv.slice(2);
if (mode === "run" && args.includes("--help")) {
  process.stdout.write("--format --session --agent --dir --title\\n");
  process.exit(0);
}
if (mode === "run") {
  const session = args.includes("--session") ? args[args.indexOf("--session") + 1] : "ses_tmux_fixture";
  process.stdout.write(JSON.stringify({ type: "step_start", sessionID: session }) + "\\n");
  setInterval(() => {}, 1000);
} else {
  process.stderr.write("unsupported fake opencode command\\n");
  process.exit(2);
}
`, "utf8");
    await chmod(fakeOpenCode, 0o700);
    const realTmuxMonitor = new OpenCodeTmuxMonitor({ stateRoot: join(temp, "tmux-monitor-state"), command: fakeOpenCode, readyTimeoutMs: 5_000 });
    let terminal;
    try {
      terminal = await realTmuxMonitor.start({
        audit: { id: "audit-tmux-fixture", name: "tmux 集成测试" },
        repository: { path: canonicalRepositoryRoot },
        environment: { OPENCODE_CONFIG: join(canonicalRepositoryRoot, ".opencode", "opencode.json") },
        args: ["run", "--format", "json", "--agent", "security-audit-orchestrator", "--dir", canonicalRepositoryRoot, "--title", "tmux 集成测试", "fixture prompt"],
      });
      assert.equal(terminal.live, true);
      assert.equal(terminal.provider_session_id, "ses_tmux_fixture");
      assert.match(await realTmuxMonitor.capture(terminal), /ses_tmux_fixture/);
      assert.match(terminal.attach_command, /^tmux -L owa-/);
      assert.equal(terminal.opencode_command, "opencode -s ses_tmux_fixture");
      await realTmuxMonitor.stop(terminal);
      terminal = await realTmuxMonitor.start({
        audit: { id: "audit-tmux-fixture", name: "tmux 恢复集成测试" },
        repository: { path: canonicalRepositoryRoot },
        environment: { OPENCODE_CONFIG: join(canonicalRepositoryRoot, ".opencode", "opencode.json") },
        providerSessionId: "ses_existing_fixture",
        args: ["run", "--format", "json", "--session", "ses_existing_fixture", "--agent", "security-audit-orchestrator", "--dir", canonicalRepositoryRoot, "--title", "tmux 恢复集成测试", "fixture recovery prompt"],
      });
      assert.equal(terminal.provider_session_id, "ses_existing_fixture");
      assert.equal(terminal.resumed, true);
    } finally {
      if (terminal) await realTmuxMonitor.stop(terminal);
    }
  }

  const relayOutputPath = join(temp, "terminal-relay-output.jsonl");
  const relayExitPath = join(temp, "terminal-relay-exit.json");
  const relaySpecPath = join(temp, "terminal-relay-spec.json");
  await writeFile(relayOutputPath, '{"type":"step_start","sessionID":"ses_relay_fixture"}\n', "utf8");
  await writeFile(relayExitPath, '{"code":0,"signal":null,"error":null}\n', "utf8");
  await writeFile(relaySpecPath, `${JSON.stringify({ output_path: relayOutputPath, exit_path: relayExitPath })}\n`, "utf8");
  const relayClient = resolve(OPENCODE, "web/dynamic-validation-observatory/terminal-output-relay.mjs");
  const relayResult = await execFileAsync(process.execPath, [relayClient, relaySpecPath], { encoding: "utf8", timeout: 5_000 });
  assert.match(relayResult.stdout, /ses_relay_fixture/);

  const validationAuditId = "web-xss-fixture";
  const validationAuditRoot = join(runtimeRoot, validationAuditId);
  await mkdir(validationAuditRoot, { recursive: true });
  const validationRequest = buildWebXssRuntimeRequest(fixtureCommit, { auditId: validationAuditId });
  const requestPath = join(validationAuditRoot, "request.json");
  const requestBytes = `${JSON.stringify(validationRequest, null, 2)}\n`;
  await writeFile(requestPath, requestBytes, "utf8");
  const validationEnvelope = buildWebXssInputEnvelope({ request: validationRequest, requestPath, requestBytes });
  await writeFile(join(validationAuditRoot, "envelope-input.json"), `${JSON.stringify(validationEnvelope, null, 2)}\n`, "utf8");

  const snapshot = await buildWorkspaceSnapshot({ reportsRoot });
  assert.equal(snapshot.summary.audit_count, 4);
  assert.equal(snapshot.summary.finding_count, 1);
  assert.equal(snapshot.summary.report_count, 3);
  assert(snapshot.reports.every(report => /^[a-f0-9]{64}$/.test(report.sha256)));
  assert.equal(snapshot.audits.find(audit => audit.id === "audit-history").progress, 63);
  assert.equal(snapshot.audits.find(audit => audit.id === "audit-history").stage, "制品不连续");
  assert.equal(snapshot.audits.find(audit => audit.id === "audit-history").progress_source, "legacy-artifact-heuristic");
  assert.equal(snapshot.reports.find(report => report.audit_id === "audit-history").integrity_state, "digest_only");
  assert.equal(snapshot.reports.find(report => report.audit_id === "audit-sealed").integrity_state, "verified_model");
  assert.equal(snapshot.reports.find(report => report.audit_id === "audit-sealed").model_digest, verifiedModel.manifest_digest);
  assert.equal(snapshot.reports.find(report => report.audit_id === "audit-mismatch").integrity_state, "model_mismatch");
  const localTodoSnapshot = await buildWorkspaceSnapshot({
    reportsRoot,
    runnerAudits: [{
      id: "audit-local-todo",
      name: "本地任务进度测试",
      status: "running",
      repository_id: "fixture",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      stage_delivery_enforcement: "TODO_ENFORCED",
      todo: { total: 4, done: 1, gap: 1, pending: 1, running: 1, failed: 0, progress: 50, complete: false },
    }],
  });
  const localTodoAudit = localTodoSnapshot.audits.find(audit => audit.id === "audit-local-todo");
  assert.equal(localTodoAudit.progress, 50);
  assert.equal(localTodoAudit.progress_source, "local-audit-todo");
  assert.equal(localTodoAudit.stage, "多维漏洞审计 · 1/4");
  assert(snapshot.reports.find(report => report.audit_id === "audit-mismatch").integrity_issues.includes("final-report-not-deterministic-render"));
  assert.equal(snapshot.findings[0].id, "F-001");
  assert.equal(snapshot.findings[0].description, "服务未校验记录归属。");
  assert.equal(snapshot.findings[0].remediation, "按当前主体校验记录所有权。");
  assert.equal(snapshot.findings[0].residual_uncertainty, "运行时路由部署状态未确认。");
  assert.deepEqual(snapshot.findings[0].source_finding_ids, ["SOURCE-001"]);
  assert.equal(snapshot.findings[0].locations[0].detail, "缺少 ownership guard");

  // The OpenCode process can end after it has sealed the deterministic model but
  // before the Markdown renderer writes its output.  The workbench must repair
  // that exact artifact locally instead of requiring an audit retry.
  const repairModel = finalReportModel("audit-report-repair");
  await writeFile(join(reportsRoot, "final", "security-audit-report-model.audit-report-repair.json"), `${JSON.stringify(repairModel, null, 2)}\n`, "utf8");
  const reportRepair = await materializeFinalReportFromModel({ reportsRoot, auditId: "audit-report-repair" });
  assert.equal(reportRepair.available, true);
  assert.equal(reportRepair.materialized, true);
  assert.equal(reportRepair.artifact.path, "final/security-audit-report.audit-report-repair.md");
  const repairedSnapshot = await buildWorkspaceSnapshot({ reportsRoot });
  assert.equal(repairedSnapshot.reports.find(report => report.audit_id === "audit-report-repair").integrity_state, "verified_model");

  const v2Findings = findingsFromArtifacts([{
    kind: "correlation",
    audit_id: "audit-finding-v2",
    path: "correlation/finding-v2.json",
    data: {
      canonical_findings: [{
        finding_schema_version: 2,
        finding_id: "FIND-V2-001",
        state: "SUPPORTED_STATIC",
        classification: {
          vulnerability_type_id: "JW-AUTHN-01",
          dimension_claims: [{ dimension: "D2", rationale: "认证边界受影响。" }],
        },
        locations: {
          primary: { file: "src/Auth.java", line_start: 42, line_end: 44, source_digest: "a".repeat(64) },
        },
        evidence: {
          facts: [
            { kind: "source", claim: "认证头由攻击者控制。", locator: { file: "src/Auth.java", line_start: 42, source_digest: "a".repeat(64) } },
            { kind: "sink", claim: "令牌解析器在认证边界使用该值。", locator: { file: "src/Auth.java", line_start: 44, source_digest: "a".repeat(64) } },
          ],
        },
        attack_surface: { impact: { outcome: "伪造令牌可能建立攻击者选择的身份。" } },
        reachability: { state: "static-reachable" },
        attacker_influence: { state: "direct" },
        severity: { rationale: "认证边界可达且输入可控。" },
        remediation: { summary: "在使用声明前校验令牌。" },
        uncertainty: { assumptions: ["尚未进行运行时部署验证。"] },
        source_findings: [{ finding_id: "SOURCE-V2-001" }],
        contradictions: [],
      }],
    },
  }]);
  assert.equal(v2Findings.length, 1);
  assert.equal(v2Findings[0].title, "漏洞类型：JW-AUTHN-01");
  assert.equal(v2Findings[0].location.path, "src/Auth.java");
  assert.equal(v2Findings[0].location.line, 42);
  assert.equal(v2Findings[0].location_complete, true);
  assert.equal(v2Findings[0].locations[1].line, 44);
  assert.equal(v2Findings[0].description, "伪造令牌可能建立攻击者选择的身份。");
  assert.equal(v2Findings[0].evidence.length, 2);
  assert.equal(v2Findings[0].remediation, "在使用声明前校验令牌。");
  assert.equal(v2Findings[0].residual_uncertainty, "尚未进行运行时部署验证。");
  assert.equal(v2Findings[0].status, "supported_static");

  const malformedReportsRoot = join(temp, "malformed-workspace-reports");
  const malformedAuditId = "audit-malformed-artifact";
  await mkdir(join(malformedReportsRoot, "vulnerability-mining"), { recursive: true });
  await mkdir(join(malformedReportsRoot, "stage-deliveries", malformedAuditId), { recursive: true });
  await writeFile(join(malformedReportsRoot, "vulnerability-mining", "malformed.json"), `${JSON.stringify({ audit_id: malformedAuditId, findings: {} })}\n`, "utf8");
  await writeFile(join(malformedReportsRoot, "stage-deliveries", malformedAuditId, "scope.r1.json"), `${JSON.stringify({
    schema_version: 1,
    audit_id: malformedAuditId,
    stage_id: "scope",
    round: 1,
    status: "PARTIAL",
    input_artifacts: {},
    output_artifacts: {},
    predecessor_manifests: {},
    validation_results: {},
  })}\n`, "utf8");
  const malformedSnapshot = await buildWorkspaceSnapshot({
    reportsRoot: malformedReportsRoot,
    runnerAudits: [{ id: malformedAuditId, name: "畸形制品隔离测试", status: "running", repository_id: "fixture", created_at: new Date().toISOString(), updated_at: new Date().toISOString(), stage_delivery_enforcement: "ENFORCED" }],
  });
  assert.equal(malformedSnapshot.audits.some(audit => audit.id === malformedAuditId), true);
  assert.equal(malformedSnapshot.summary.active_audits, 1);
  assert.equal(Array.isArray(malformedSnapshot.findings), true);

  const objectRegistryStateRoot = join(temp, "object-registry-state");
  await mkdir(objectRegistryStateRoot, { recursive: true });
  await writeFile(join(objectRegistryStateRoot, "repositories.json"), `${JSON.stringify({
    schema_version: 1,
    repositories: { fixture: { name: "对象形态仓库", path: canonicalRepositoryRoot } },
  })}\n`, "utf8");
  const objectRegistryRunner = new AuditRunner({ stateRoot: objectRegistryStateRoot, platformRoot, configPath: join(repositoryRoot, ".opencode", "opencode.json") });
  await objectRegistryRunner.ready;
  assert.equal((await objectRegistryRunner.listRepositories()).some(repository => repository.id === "fixture"), true);
  assert.equal(Array.isArray(JSON.parse(await readFile(join(objectRegistryStateRoot, "repositories.json"), "utf8")).repositories), true);
  await objectRegistryRunner.shutdown();

  let spawnCall = null;
  const child = new FakeChild();
  const terminalMonitor = new FakeTerminalMonitor();
  const dynamicChild = new FakeChild();
  let dynamicSpawnCall = null;
  const runner = new AuditRunner({
    stateRoot,
    platformRoot,
    repositories: [{ id: "fixture", name: "测试仓库", path: repositoryRoot }],
    configPath: join(repositoryRoot, ".opencode", "opencode.json"),
    enabled: true,
    environment: { ...process.env, http_proxy: "http://proxy-fixture.test:8080", HTTPS_PROXY: "http://secure-proxy-fixture.test:8443" },
    terminalMonitor,
    spawnProcess(command, args, options) {
      spawnCall = { command, args, options };
      return child;
    },
  });
  await runner.ready;
  let fallbackSpawnCall = null;
  const fallbackChild = new FakeChild();
  const fallbackRunner = new AuditRunner({
    stateRoot: join(temp, "fallback-state"),
    platformRoot,
    repositories: [{ id: "fixture", name: "测试仓库", path: repositoryRoot }],
    configPath: join(repositoryRoot, ".opencode", "opencode.json"),
    enabled: true,
    terminalMonitor: {
      async probe() { return { available: false, message: "未找到 tmux。", opencode_command: "C:\\tools\\opencode.exe" }; },
      async stop() {},
    },
    stageDeliveryVerifier: async ({ auditId }) => ({
      enforcement: "ENFORCED",
      audit_id: auditId,
      complete: true,
      completed_count: 8,
      stages: [],
      errors: [],
    }),
    todoCompletionVerifier: async () => ({ complete: true, errors: [], summary: { total: 1, done: 1, gap: 0, pending: 0, running: 0, failed: 0, progress: 100, complete: true }, final_report_path: "final/security-audit-report.audit-fallback-001.md" }),
    spawnProcess(command, args, options) {
      fallbackSpawnCall = { command, args, options };
      return fallbackChild;
    },
  });
  await fallbackRunner.ready;
  const fallbackAudit = await fallbackRunner.createAudit({ audit_id: "audit-fallback-001", repository_id: "fixture", ref: "HEAD", allow_dirty: true }, "fallback-request-001");
  for (let attempt = 0; attempt < 100 && !["running", "failed"].includes(fallbackRunner.getAudit(fallbackAudit.id)?.status); attempt += 1) await new Promise(resolve => setTimeout(resolve, 2));
  assert.equal(fallbackRunner.getAudit(fallbackAudit.id).status, "running", String(fallbackRunner.getAudit(fallbackAudit.id).error ?? "fallback runner 未进入运行状态"));
  assert.equal(fallbackSpawnCall.command, "C:\\tools\\opencode.exe");
  assert.deepEqual(fallbackSpawnCall.args.slice(0, 6), ["run", "--format", "json", "--agent", "security-audit-orchestrator", "--dir"]);
  assert.equal(fallbackSpawnCall.args[6], join(platformRoot, "workspace", "audit-runs", "audit-fallback-001"));
  assert.equal(fallbackSpawnCall.options.cwd, join(platformRoot, "workspace", "audit-runs", "audit-fallback-001"));
  assert.equal(fallbackRunner.getAudit(fallbackAudit.id).terminal.status, "unavailable");
  fallbackChild.stdout.write('{"type":"step_start","sessionID":"ses_fallback_fixture"}\n');
  for (let attempt = 0; attempt < 50 && !fallbackRunner.getAudit(fallbackAudit.id).provider_session_id; attempt += 1) await new Promise(resolve => setImmediate(resolve));
  assert.equal(fallbackRunner.getAudit(fallbackAudit.id).provider_session_id, "ses_fallback_fixture");
  fallbackChild.emit("close", 0, null);
  for (let attempt = 0; attempt < 50 && !(await fallbackRunner.eventsSince(fallbackAudit.id)).some(event => event.type === "audit.completed"); attempt += 1) await new Promise(resolve => setImmediate(resolve));
  assert.equal(fallbackRunner.getAudit(fallbackAudit.id).status, "completed");
  assert.equal(fallbackRunner.getAudit(fallbackAudit.id).todo_completion.complete, true);
  const sourceBinding = JSON.parse(await readFile(join(platformRoot, "reports", "repositories", "fixture", "platform", "audit-runs", fallbackAudit.id, "source-binding.json"), "utf8"));
  assert.equal(sourceBinding.audit_id, fallbackAudit.id);
  assert.equal(sourceBinding.task_context.quick_dynamic_opt_in, false);
  assert.match(sourceBinding.binding_digest, /^[a-f0-9]{64}$/);
  await fallbackRunner.shutdown();

  const gatedChild = new FakeChild();
  const gatedRunner = new AuditRunner({
    stateRoot: join(temp, "gated-state"),
    platformRoot,
    repositories: [{ id: "fixture", name: "测试仓库", path: repositoryRoot }],
    configPath: join(repositoryRoot, ".opencode", "opencode.json"),
    enabled: true,
    terminalMonitor: {
      async probe() { return { available: false, message: "未找到 tmux。" }; },
      async stop() {},
    },
    stageDeliveryVerifier: async ({ auditId }) => ({
      enforcement: "ENFORCED",
      audit_id: auditId,
      complete: false,
      completed_count: 6,
      stages: [],
      errors: ["validation:artifact-missing"],
    }),
    todoCompletionVerifier: async () => ({ complete: false, errors: ["仍有 2 项 PENDING。"], summary: { total: 2, done: 0, gap: 0, pending: 2, running: 0, failed: 0, progress: 0, complete: false }, final_report_path: null }),
    spawnProcess() { return gatedChild; },
  });
  await gatedRunner.ready;
  const gatedAudit = await gatedRunner.createAudit({ audit_id: "audit-gated-001", repository_id: "fixture", ref: "HEAD", allow_dirty: true }, "gated-request-001");
  for (let attempt = 0; attempt < 100 && !["running", "failed"].includes(gatedRunner.getAudit(gatedAudit.id)?.status); attempt += 1) await new Promise(resolve => setTimeout(resolve, 2));
  assert.equal(gatedRunner.getAudit(gatedAudit.id).status, "running", String(gatedRunner.getAudit(gatedAudit.id).error ?? "stage gate runner 未进入运行状态"));
  gatedChild.emit("close", 0, null);
  for (let attempt = 0; attempt < 100 && gatedRunner.getAudit(gatedAudit.id)?.status === "running"; attempt += 1) await new Promise(resolve => setImmediate(resolve));
  assert.equal(gatedRunner.getAudit(gatedAudit.id).status, "interrupted");
  assert.equal(gatedRunner.getAudit(gatedAudit.id).interruption_reason, "local-audit-todo-incomplete");
  assert.match(gatedRunner.getAudit(gatedAudit.id).error, /2 项 PENDING/);
  await gatedRunner.shutdown();

  // A live OpenCode run can enter its own wait/continue loop after all durable
  // work is complete. The watchdog must use only the local todo plus final
  // report gate, accept a terminal GAP, and terminate that runner itself.
  const terminalGapChild = new FakeChild();
  const terminalGapMonitor = new FakeTerminalMonitor();
  const terminalGapRunner = new AuditRunner({
    stateRoot: join(temp, "terminal-gap-watchdog-state"),
    platformRoot,
    repositories: [{ id: "fixture", name: "测试仓库", path: repositoryRoot }],
    configPath: join(repositoryRoot, ".opencode", "opencode.json"),
    enabled: true,
    terminalMonitor: terminalGapMonitor,
    completionWatchdogIntervalMs: 3_600_000,
    todoCompletionVerifier: async () => ({
      complete: true,
      errors: [],
      summary: { total: 2, done: 1, gap: 1, pending: 0, running: 0, failed: 0, progress: 100, complete: true, next_action: "FINALIZE_WITH_RESIDUAL_GAPS" },
      final_report_path: "final/security-audit-report.audit-terminal-gap-watchdog.md",
    }),
    spawnProcess() { return terminalGapChild; },
  });
  await terminalGapRunner.ready;
  const terminalGapAudit = await terminalGapRunner.createAudit({ audit_id: "audit-terminal-gap-watchdog", repository_id: "fixture", ref: "HEAD", allow_dirty: true }, "terminal-gap-watchdog-request");
  for (let attempt = 0; attempt < 100 && terminalGapRunner.getAudit(terminalGapAudit.id)?.status !== "running"; attempt += 1) await new Promise(resolve => setTimeout(resolve, 2));
  assert.equal(terminalGapRunner.getAudit(terminalGapAudit.id).status, "running");
  assert.match(terminalGapMonitor.starts[0].args.at(-1), /FINALIZE_WITH_RESIDUAL_GAPS/);
  assert.match(terminalGapMonitor.starts[0].args.at(-1), /不得输出“继续”“等待”“下一步”/);
  assert.equal(await terminalGapRunner.runCompletionWatchdog("test-terminal-gap-watchdog"), 1);
  for (let attempt = 0; attempt < 100 && !(await terminalGapRunner.eventsSince(terminalGapAudit.id)).some(event => event.type === "audit.runner.stopped"); attempt += 1) await new Promise(resolve => setImmediate(resolve));
  const terminalGapResult = terminalGapRunner.getAudit(terminalGapAudit.id);
  assert.equal(terminalGapResult.status, "completed");
  assert.equal(terminalGapResult.completion_source, "todo-artifact-watchdog");
  assert.equal(terminalGapResult.todo_summary.gap, 1, "展示用 GAP 不得阻止任务收尾");
  assert.deepEqual(terminalGapChild.signals, ["SIGTERM"]);
  assert.equal(terminalGapMonitor.abortCalls.length, 1);
  assert.equal(terminalGapMonitor.stopCalls, 1);
  assert.equal((await terminalGapRunner.eventsSince(terminalGapAudit.id)).some(event => event.type === "audit.runner.stopped"), true);
  await terminalGapRunner.shutdown();

  // A known OpenCode timeout is recoverable.  The watchdog must interrupt the
  // stale run, retain its provider session and artifacts, then launch exactly
  // one automatic checkpoint recovery.
  const timeoutFirstChild = new FakeChild();
  const timeoutRecoveredChild = new FakeChild();
  const timeoutMonitor = new FakeTerminalMonitor();
  let timeoutSpawnCount = 0;
  const timeoutRunner = new AuditRunner({
    stateRoot: join(temp, "timeout-recovery-state"),
    platformRoot,
    repositories: [{ id: "fixture", name: "测试仓库", path: repositoryRoot }],
    configPath: join(repositoryRoot, ".opencode", "opencode.json"),
    enabled: true,
    terminalMonitor: timeoutMonitor,
    completionWatchdogIntervalMs: 3_600_000,
    todoCompletionVerifier: async () => ({
      complete: false,
      errors: ["仍有 1 项 PENDING。"],
      summary: { total: 1, done: 0, gap: 0, pending: 1, running: 0, failed: 0, progress: 0, complete: false, next_action: "CLAIM" },
      final_report_path: null,
    }),
    spawnProcess() { timeoutSpawnCount += 1; return timeoutSpawnCount === 1 ? timeoutFirstChild : timeoutRecoveredChild; },
  });
  await timeoutRunner.ready;
  const timeoutAudit = await timeoutRunner.createAudit({ audit_id: "audit-timeout-recovery", repository_id: "fixture", ref: "HEAD", allow_dirty: true }, "timeout-recovery-request");
  for (let attempt = 0; attempt < 100 && timeoutRunner.getAudit(timeoutAudit.id)?.status !== "running"; attempt += 1) await new Promise(resolve => setTimeout(resolve, 2));
  timeoutFirstChild.stdout.write("Error: The operation timed out\n");
  for (let attempt = 0; attempt < 1_000 && (timeoutSpawnCount !== 2 || timeoutRunner.getAudit(timeoutAudit.id)?.status !== "running" || timeoutRunner.getAudit(timeoutAudit.id)?.recovery_count !== 1 || timeoutRunner.getAudit(timeoutAudit.id)?.timeout_recovery?.state !== "restarted"); attempt += 1) await new Promise(resolve => setTimeout(resolve, 2));
  const timeoutResult = timeoutRunner.getAudit(timeoutAudit.id);
  assert.equal(timeoutSpawnCount, 2, "超时 watchdog 必须只启动一次断点恢复");
  assert.equal(timeoutResult.status, "running");
  assert.equal(timeoutResult.recovery_count, 1);
  assert.equal(timeoutResult.timeout_recovery.state, "restarted");
  assert.equal(timeoutResult.timeout_recovery.attempts, 1);
  assert.deepEqual(timeoutFirstChild.signals, ["SIGTERM"]);
  assert.equal(timeoutMonitor.abortCalls.length, 1);
  const timeoutEvents = await timeoutRunner.eventsSince(timeoutAudit.id);
  assert.equal(timeoutEvents.some(event => event.type === "audit.timeout.detected"), true);
  assert.equal(timeoutEvents.some(event => event.type === "audit.timeout.recovery.started"), true);
  await timeoutRunner.shutdown();

  // When all scheduled work is terminal but report sealing is malformed, the
  // watchdog must identify the required name, format and location instead of
  // presenting a generic retry-only failure.
  const deliveryDiagnosticChild = new FakeChild();
  const deliveryDiagnosticRunner = new AuditRunner({
    stateRoot: join(temp, "delivery-diagnostic-state"),
    platformRoot,
    repositories: [{ id: "fixture", name: "测试仓库", path: repositoryRoot }],
    configPath: join(repositoryRoot, ".opencode", "opencode.json"),
    enabled: true,
    terminalMonitor: {
      async probe() { return { available: false, message: "未找到 tmux。" }; },
      async stop() {},
    },
    spawnProcess() { return deliveryDiagnosticChild; },
  });
  await deliveryDiagnosticRunner.ready;
  const deliveryDiagnosticAudit = await deliveryDiagnosticRunner.createAudit({ audit_id: "audit-delivery-diagnostic", repository_id: "fixture", ref: "HEAD", allow_dirty: true }, "delivery-diagnostic-request");
  for (let attempt = 0; attempt < 100 && deliveryDiagnosticRunner.getAudit(deliveryDiagnosticAudit.id)?.status !== "running"; attempt += 1) await new Promise(resolve => setTimeout(resolve, 2));
  await writeFile(join(temp, "delivery-diagnostic-state", deliveryDiagnosticAudit.id, "audit-todo.json"), `${JSON.stringify({
    schema_version: 1,
    audit_id: deliveryDiagnosticAudit.id,
    items: [{ item_id: "todo:delivery-diagnostic", status: "DONE", agent_name: "fixture" }],
    packets: [],
  }, null, 2)}\n`, "utf8");
  await writeFile(join(reportsRoot, "final", "security-audit-report.audit-delivery-diagnostic-draft.md"), "# 错误名称的草稿\n", "utf8");
  await writeFile(join(reportsRoot, "final", "security-audit-report-model.audit-delivery-diagnostic.json"), "{\n", "utf8");
  deliveryDiagnosticChild.emit("close", 0, null);
  for (let attempt = 0; attempt < 500 && !deliveryDiagnosticRunner.getAudit(deliveryDiagnosticAudit.id)?.todo_completion; attempt += 1) await new Promise(resolve => setTimeout(resolve, 2));
  const deliveryDiagnosticResult = deliveryDiagnosticRunner.getAudit(deliveryDiagnosticAudit.id);
  assert.ok(deliveryDiagnosticResult.todo_completion, JSON.stringify(deliveryDiagnosticResult));
  const deliveryDiagnosticErrors = deliveryDiagnosticResult.todo_completion.errors.join("\n");
  assert.equal(deliveryDiagnosticResult.status, "interrupted");
  assert.match(deliveryDiagnosticErrors, /reports\/final\/security-audit-report\.audit-delivery-diagnostic\.md/);
  assert.match(deliveryDiagnosticErrors, /Markdown 候选/);
  assert.match(deliveryDiagnosticErrors, /不是有效 JSON/);
  await deliveryDiagnosticRunner.shutdown();

  // A server restart loses the child-process handle.  If the task's durable
  // completion evidence is already valid, startup must converge it to completed
  // before the UI offers a meaningless retry.
  const reconciledStateRoot = join(temp, "reconciled-state");
  const reconciledAuditId = "audit-reconciled-001";
  const reconciledTodoPath = join(reconciledStateRoot, reconciledAuditId, "audit-todo.json");
  await mkdir(join(reconciledStateRoot, reconciledAuditId), { recursive: true });
  await writeFile(join(reconciledStateRoot, reconciledAuditId, "run.json"), `${JSON.stringify({
    id: reconciledAuditId,
    name: "重启收敛测试",
    repository_id: "fixture",
    repository_name: "测试仓库",
    status: "interrupted",
    version: 1,
    event_sequence: 0,
    created_at: "2026-08-15T00:00:00.000Z",
    updated_at: "2026-08-15T00:00:00.000Z",
    started_at: "2026-08-15T00:00:00.000Z",
    finished_at: "2026-08-15T00:01:00.000Z",
    todo_path: reconciledTodoPath,
    stage_delivery_enforcement: "TODO_ENFORCED",
    interruption_reason: "workbench-restarted",
    error: "工作台服务已重启，原 Runner 连接已中断。",
  }, null, 2)}\n`, "utf8");
  const reconciledRunner = new AuditRunner({
    stateRoot: reconciledStateRoot,
    platformRoot,
    repositories: [{ id: "fixture", name: "测试仓库", path: repositoryRoot }],
    configPath: join(repositoryRoot, ".opencode", "opencode.json"),
    terminalMonitor: { async stop() {} },
    todoCompletionVerifier: async () => ({
      complete: true,
      errors: [],
      summary: { total: 1, done: 1, gap: 0, pending: 0, running: 0, failed: 0, progress: 100, complete: true },
      final_report_path: "final/security-audit-report.audit-reconciled-001.md",
    }),
  });
  await reconciledRunner.ready;
  assert.equal(reconciledRunner.getAudit(reconciledAuditId).status, "completed");
  assert.equal(reconciledRunner.getAudit(reconciledAuditId).completion_source, "todo-artifact-verification");
  assert.equal((await reconciledRunner.eventsSince(reconciledAuditId)).some(event => event.type === "audit.completed"), true);
  await reconciledRunner.shutdown();

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
  assert.equal(repositories[0].config_valid, true);
  assert.equal(repositories[0].git_repository, true);
  assert.equal(repositories[0].ready, true);
  assert.equal(repositories[0].readiness, "ready");
  assert.equal(repositories[0].dirty, false);
  assert.equal(repositories[0].audit_count, 0);
  assert.equal(repositories[0].directory, canonicalRepositoryRoot);

  const fakeBin = join(temp, "fake-bin");
  const healthConfig = join(temp, "health-opencode.json");
  await writeFile(healthConfig, `${JSON.stringify({
    mcp: { "chrome-devtools": { enabled: true, command: ["npx", "chrome-devtools-mcp"] } },
  })}\n`, "utf8");
  let versionProbeCount = 0;
  const environmentService = new EnvironmentHealthService({
    projectRoot: resolve(OPENCODE, ".."),
    configPaths: [healthConfig],
    environment: { PATH: fakeBin, OPENCODE_BIN: join(fakeBin, "opencode"), JOERN_BIN: join(fakeBin, "joern"), JOERN_PARSE_BIN: join(fakeBin, "joern-parse"), OPENGREP_BIN: join(fakeBin, "opengrep"), JOERN_JAVA_BIN: fakeBin },
    platform: "linux",
    architecture: "x64",
    nodeVersion: "22.12.0",
    async resolveCommand(command) { return command; },
    async execute(command) {
      versionProbeCount += 1;
      return { stdout: `${basename(command)} 1.0.0\n`, stderr: "" };
    },
  });
  const health = await environmentService.snapshot();
  assert.equal(health.platform.os, "linux");
  assert.equal(health.configuration.valid, 1);
  assert(health.capabilities.every(item => item.status === "ready"));
  assert.equal(health.components.some(item => item.id === "coverage_ledger"), false);
  assert.equal(health.components.find(item => item.id === "chrome_devtools_mcp").status, "ready");
  const cachedProbeCount = versionProbeCount;
  await environmentService.snapshot();
  assert.equal(versionProbeCount, cachedProbeCount);

  let windowsChromeLaunches = 0;
  const windowsHealthService = new EnvironmentHealthService({
    projectRoot: resolve(OPENCODE, ".."),
    configPaths: [healthConfig],
    environment: { PATH: "C:\\tools", PATHEXT: ".EXE;.CMD", PROGRAMFILES: "C:\\Program Files" },
    platform: "win32",
    architecture: "x64",
    nodeVersion: "22.12.0",
    async resolveCommand(command) {
      const value = String(command).toLowerCase();
      if (value.includes("chrome.exe")) return command;
      if (value === "tmux.exe" || value === "tmux") return null;
      if (value === "psmux.exe") return "C:\\tools\\psmux.exe";
      if (value === "opencode.exe") return "C:\\tools\\opencode.exe";
      return command;
    },
    async execute(command) {
      if (/chrome\.exe/i.test(command)) {
        windowsChromeLaunches += 1;
        throw new Error("Windows Chrome probe must not launch the browser");
      }
      return { stdout: /psmux/i.test(command) ? "psmux 3.test\n" : `${basename(command)} 1.0.0\n`, stderr: "" };
    },
  });
  const windowsHealth = await windowsHealthService.snapshot();
  assert.equal(windowsChromeLaunches, 0);
  assert.equal(windowsHealth.components.find(item => item.id === "chrome").status, "ready");
  assert.equal(windowsHealth.components.find(item => item.id === "tmux").status, "ready");
  assert.match(windowsHealth.components.find(item => item.id === "tmux").detail, /psmux/);

  const windowsMonitorCalls = [];
  const windowsMonitor = new OpenCodeTmuxMonitor({
    stateRoot: join(temp, "windows-psmux-state"),
    platform: "win32",
    environment: { PATH: "C:\\tools", PATHEXT: ".EXE" },
    async resolveCommand(command) {
      const value = String(command).toLowerCase();
      if (value === "opencode.exe") return "C:\\tools\\opencode.exe";
      if (value === "psmux.exe") return "C:\\tools\\psmux.exe";
      return null;
    },
    async execute(command, args) {
      windowsMonitorCalls.push({ command, args });
      if (/opencode\.exe$/i.test(command)) return { stdout: "--format --session --agent --dir --title\n", stderr: "" };
      if (/psmux\.exe$/i.test(command) && args[0] === "-V") return { stdout: "psmux 3.test\n", stderr: "" };
      throw new Error(`unexpected command: ${command}`);
    },
  });
  const windowsMonitorProbe = await windowsMonitor.probe();
  assert.equal(windowsMonitorProbe.available, true);
  assert.equal(windowsMonitorProbe.backend, "psmux");
  assert.equal(windowsMonitorProbe.opencode_command, "C:\\tools\\opencode.exe");
  assert.equal(windowsMonitorProbe.multiplexer_command, "C:\\tools\\psmux.exe");
  assert(windowsMonitorCalls.every(call => call.command !== "opencode" && call.command !== "tmux"));

  const windowsStartCalls = [];
  const windowsStartMonitor = new OpenCodeTmuxMonitor({
    stateRoot: join(temp, "windows-psmux-start-state"),
    platform: "win32",
    environment: { PATH: "C:\\tools", PATHEXT: ".EXE" },
    async execute(command, args) {
      windowsStartCalls.push({ command, args });
      const operation = args[2];
      if (operation === "kill-server") return { stdout: "", stderr: "" };
      if (operation === "new-session") {
        const boundary = args.indexOf("--");
        assert(boundary > 0, `psmux ${operation} 缺少命令边界 --`);
        assert.equal(args[boundary + 1], process.execPath);
        return { stdout: "", stderr: "" };
      }
      if (operation === "capture-pane") return { stdout: "Windows psmux OpenCode TUI\n", stderr: "" };
      throw new Error(`unexpected psmux operation: ${operation}`);
    },
  });
  windowsStartMonitor.probeResult = {
    available: true,
    backend: "psmux",
    opencode_command: "C:\\tools\\opencode.exe",
    multiplexer_command: "C:\\tools\\psmux.exe",
  };
  windowsStartMonitor.command = "C:\\tools\\opencode.exe";
  windowsStartMonitor.tmuxCommand = "C:\\tools\\psmux.exe";
  windowsStartMonitor.multiplexerBackend = "psmux";
  const windowsTerminal = await windowsStartMonitor.start({
    audit: { id: "audit-windows-psmux", name: "Windows psmux 集成测试" },
    repository: { path: canonicalRepositoryRoot },
    executionDirectory: canonicalRepositoryRoot,
    environment: { http_proxy: "http://proxy-fixture.test:8080", HTTPS_PROXY: "http://secure-proxy-fixture.test:8443" },
    args: ["run", "--format", "json", "--agent", "security-audit-orchestrator", "--dir", canonicalRepositoryRoot, "--title", "Windows psmux 集成测试", "fixture prompt"],
  });
  assert.equal(windowsTerminal.backend, "psmux");
  assert.equal(windowsTerminal.provider_session_id, null);
  assert.equal(windowsStartCalls.filter(call => call.args[2] === "new-session").length, 1);
  const windowsRunSpec = JSON.parse(await readFile(join(temp, "windows-psmux-start-state", "audit-windows-psmux", "tmux-run.json"), "utf8"));
  assert.equal(windowsRunSpec.command, "C:\\tools\\opencode.exe");
  assert.equal(windowsRunSpec.args[0], "run");
  assert.equal(windowsRunSpec.args.includes("serve"), false);
  assert.equal(windowsRunSpec.environment.http_proxy, "http://proxy-fixture.test:8080");
  assert.equal(windowsRunSpec.environment.HTTPS_PROXY, "http://secure-proxy-fixture.test:8443");

  // psmux may create a valid OpenCode process before its pane exposes any
  // output.  That is not a launch failure and must not trigger the old 60-second
  // fallback to the unmonitored runner.
  const silentPsmuxMonitor = new OpenCodeTmuxMonitor({
    stateRoot: join(temp, "windows-psmux-silent-state"),
    platform: "win32",
    environment: { PATH: "C:\\tools", PATHEXT: ".EXE" },
    async execute(_command, args) {
      const operation = args[2];
      if (operation === "kill-server" || operation === "new-session") return { stdout: "", stderr: "" };
      if (operation === "capture-pane") return { stdout: "", stderr: "" };
      throw new Error(`unexpected silent psmux operation: ${operation}`);
    },
  });
  silentPsmuxMonitor.probeResult = { available: true, backend: "psmux", opencode_command: "C:\\tools\\opencode.exe", multiplexer_command: "C:\\tools\\psmux.exe" };
  silentPsmuxMonitor.command = "C:\\tools\\opencode.exe";
  silentPsmuxMonitor.tmuxCommand = "C:\\tools\\psmux.exe";
  silentPsmuxMonitor.multiplexerBackend = "psmux";
  const silentPsmuxTerminal = await Promise.race([
    silentPsmuxMonitor.start({
      audit: { id: "audit-windows-psmux-silent", name: "Windows psmux 静默启动测试" },
      repository: { path: canonicalRepositoryRoot },
      executionDirectory: canonicalRepositoryRoot,
      environment: {},
      args: ["run", "--format", "json", "--agent", "security-audit-orchestrator", "--dir", canonicalRepositoryRoot, "--title", "Windows psmux 静默启动测试", "fixture prompt"],
    }),
    new Promise((_, reject) => setTimeout(() => reject(new Error("psmux 静默启动被输出门禁阻塞。")), 500)),
  ]);
  assert.equal(silentPsmuxTerminal.backend, "psmux");
  assert.match(silentPsmuxTerminal.message, /异步输出/);

  // Some psmux versions can report a successful but temporarily empty pane
  // capture. The launcher diagnostic stream remains the reliable fallback.
  const psmuxDiagnosticOutputPath = join(temp, "windows-psmux-diagnostic-output.jsonl");
  await writeFile(psmuxDiagnosticOutputPath, '{"type":"step_start","sessionID":"ses_psmux_diagnostic"}\n', "utf8");
  const psmuxDiagnosticMonitor = new OpenCodeTmuxMonitor({
    stateRoot: join(temp, "windows-psmux-diagnostic-state"),
    platform: "win32",
    async execute(_command, args) {
      assert.equal(args[2], "capture-pane");
      return { stdout: "", stderr: "" };
    },
  });
  psmuxDiagnosticMonitor.tmuxCommand = "C:\\tools\\psmux.exe";
  const psmuxDiagnosticOutput = await psmuxDiagnosticMonitor.capture({
    socket_name: "owa-0123456789abcdef",
    target: "audit:tui",
    output_path: psmuxDiagnosticOutputPath,
  });
  assert.match(psmuxDiagnosticOutput, /ses_psmux_diagnostic/);

  const findingWorkflowRoot = join(temp, "finding-workflow");
  const findingWorkflow = new FindingWorkflowStore({ stateRoot: findingWorkflowRoot });
  await findingWorkflow.ready;
  let findingResourceId;

  const server = createAuditWorkbenchServer({ stateRoot, runtimeRoot, runner, dynamicRunner, environmentService, findingWorkflow });
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
    assert.match(workspace.findings[0].resource_id, /^[a-f0-9]{24}$/);
    assert.equal(workspace.findings[0].repository_id, "fixture");
    assert.equal(workspace.findings[0].repository_name, "测试仓库");
    assert.equal(workspace.findings[0].workflow.status, "unreviewed");
    assert.equal(workspace.findings[0].workflow.version, 0);
    const repositoryResponse = await fetch(`${base}/api/v1/repositories`);
    assert.equal(repositoryResponse.status, 200);
    const repositoryPayload = await repositoryResponse.json();
    assert.equal(repositoryPayload.items[0].audit_count, 11);
    assert.equal(repositoryPayload.items[0].active_audit_count, 0);
    const relativeProjectResponse = await fetch(`${base}/api/v1/repositories`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "project-relative" },
      body: JSON.stringify({ path: "../relative-project" }),
    });
    assert.equal(relativeProjectResponse.status, 422);
    const projectResponse = await fetch(`${base}/api/v1/repositories`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "project-001" },
      body: JSON.stringify({ path: operatorSelectedRoot, name: "操作员指定项目" }),
    });
    assert.equal(projectResponse.status, 201);
    const selectedProject = await projectResponse.json();
    assert.match(selectedProject.id, /^project-[a-f0-9]{12}$/);
    assert.equal(selectedProject.name, "操作员指定项目");
    assert.equal(selectedProject.directory, canonicalOperatorSelectedRoot);
    assert.equal(selectedProject.configured, true);
    assert.equal(selectedProject.ready, true);
    const duplicateProjectResponse = await fetch(`${base}/api/v1/repositories`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "project-002" },
      body: JSON.stringify({ path: operatorSelectedRoot, name: "另一个名称" }),
    });
    assert.equal(duplicateProjectResponse.status, 201);
    assert.equal((await duplicateProjectResponse.json()).id, selectedProject.id);
    const projectsAfterRegistration = await (await fetch(`${base}/api/v1/repositories`)).json();
    assert.equal(projectsAfterRegistration.count, 2);
    const historyReport = workspace.reports.find(item => item.audit_id === "audit-history");
    assert.match(historyReport.id, /^[a-f0-9]{24}$/);
    assert.notEqual(historyReport.id, snapshot.reports.find(item => item.audit_id === "audit-history").id);

    const environmentResponse = await fetch(`${base}/api/v1/environment`);
    assert.equal(environmentResponse.status, 200);
    const environment = await environmentResponse.json();
    assert.equal(environment.capabilities.find(item => item.id === "static").status, "ready");
    assert.equal(environment.components.find(item => item.id === "chrome").status, "ready");

    findingResourceId = workspace.findings[0].resource_id;
    const workflowResponse = await fetch(`${base}/api/v1/findings/${findingResourceId}/workflow`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": '"0"', "Idempotency-Key": "finding-workflow-001" },
      body: JSON.stringify({ status: "confirmed", note: "Owner 已确认该权限校验缺失。" }),
    });
    assert.equal(workflowResponse.status, 200);
    const workflow = await workflowResponse.json();
    assert.equal(workflow.status, "confirmed");
    assert.equal(workflow.note, "Owner 已确认该权限校验缺失。");
    assert.equal(workflow.version, 1);
    assert.equal(workflow.idempotency_records, undefined);
    assert.equal(workflowResponse.headers.get("etag"), '"1"');
    const workspaceAfterWorkflow = await (await fetch(`${base}/api/v1/workspace`)).json();
    assert.equal(workspaceAfterWorkflow.findings[0].workflow.status, "confirmed");
    const staleWorkflowResponse = await fetch(`${base}/api/v1/findings/${findingResourceId}/workflow`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": '"0"', "Idempotency-Key": "finding-workflow-stale" },
      body: JSON.stringify({ status: "rejected", note: "stale" }),
    });
    assert.equal(staleWorkflowResponse.status, 412);
    const conflictingWorkflowResponse = await fetch(`${base}/api/v1/findings/${findingResourceId}/workflow`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": '"1"', "Idempotency-Key": "finding-workflow-001" },
      body: JSON.stringify({ status: "rejected", note: "同一幂等键不得改变操作。" }),
    });
    assert.equal(conflictingWorkflowResponse.status, 409);
    const invalidWorkflowResponse = await fetch(`${base}/api/v1/findings/${findingResourceId}/workflow`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": '"1"', "Idempotency-Key": "finding-workflow-invalid" },
      body: JSON.stringify({ status: "arbitrary", note: "invalid" }),
    });
    assert.equal(invalidWorkflowResponse.status, 422);

    const reportResponse = await fetch(`${base}/api/v1/reports/${historyReport.id}`);
    assert.equal(reportResponse.status, 200);
    const report = await reportResponse.json();
    assert.match(report.body, /^# 安全审计报告/);
    assert.equal(report.rendering, "markdown-it-html-disabled");
    assert.match(report.rendered_html, /<h1>安全审计报告<\/h1>/);
    assert.match(report.rendered_html, /<table>/);
    assert.doesNotMatch(report.rendered_html, /<script>/i);
    assert.doesNotMatch(report.rendered_html, /href=["']javascript:/i);
    assert.equal(report.sha256, historyReport.sha256);
    assert.equal(report.integrity_state, "digest_only");
    const reportDownload = await fetch(`${base}/api/v1/reports/${historyReport.id}/download`);
    assert.equal(reportDownload.status, 200);
    assert.match(reportDownload.headers.get("content-disposition"), /security-audit-report\.audit-history\.md/);
    assert.equal(await reportDownload.text(), report.body);
    assert.equal((await fetch(`${base}/api/v1/reports/not-found`)).status, 404);

    const createResponse = await fetch(`${base}/api/v1/audits`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "request-001" },
      body: JSON.stringify({
        audit_id: "audit-live-001",
        name: "发布前安全审计; touch /tmp/never",
        repository_id: "fixture",
        ref: "HEAD",
        allow_dirty: true,
        additional_instructions_enabled: true,
        additional_instructions: "只验证 XSS 漏洞；其他类型只记录静态证据。",
        test_environment_enabled: true,
        test_environment_context: "URL: http://127.0.0.1:8080\nAttacker: attacker-fixture / context-attacker-secret\nVictim: victim-fixture / context-victim-secret",
      }),
    });
    assert.equal(createResponse.status, 202);
    const created = await createResponse.json();
    assert.equal(created.id, "audit-live-001");
    assert.equal(created.idempotency_digest, undefined);
    assert.equal(created.private_context, undefined);
    assert.equal(created.task_context.additional_instructions_enabled, true);
    assert.equal(created.task_context.test_environment_enabled, true);
    assert.equal(created.task_context.dynamic_validation_enabled, true);
    assert.equal(JSON.stringify(created).includes("context-attacker-secret"), false);
    assert.equal(JSON.stringify(created).includes("proxy-fixture.test"), false);

    for (let attempt = 0; attempt < 100 && runner.getAudit(created.id)?.status !== "running"; attempt += 1) await new Promise(resolve => setTimeout(resolve, 2));
    assert.equal(runner.getAudit(created.id).status, "running");
    assert.equal(spawnCall.command, process.execPath);
    assert.equal(spawnCall.options.shell, false);
    const executionWorkspace = join(platformRoot, "workspace", "audit-runs", created.id);
    assert.equal(spawnCall.options.cwd, executionWorkspace);
    assert.equal(spawnCall.options.env.OPENCODE_CONFIG, join(canonicalRepositoryRoot, ".opencode", "opencode.json"));
    assert.equal(spawnCall.options.env.OPENCODE_CONFIG_DIR, join(canonicalRepositoryRoot, ".opencode"));
    assert.equal(spawnCall.options.env.OPENCODE_DISABLE_PROJECT_CONFIG, "true");
    assert.equal(typeof spawnCall.options.env.OPENCODE_CONFIG_CONTENT, "string");
    assert.equal(Object.hasOwn(JSON.parse(spawnCall.options.env.OPENCODE_CONFIG_CONTENT).mcp, "coverage_ledger"), false);
    assert.match(spawnCall.args[0], /terminal-output-relay\.mjs$/);
    const monitoredRunArgs = terminalMonitor.starts[0].args;
    assert.deepEqual(monitoredRunArgs.slice(0, 3), ["run", "--format", "json"]);
    assert.equal(monitoredRunArgs[monitoredRunArgs.indexOf("--agent") + 1], "security-audit-orchestrator");
    assert.equal(monitoredRunArgs[monitoredRunArgs.indexOf("--dir") + 1], executionWorkspace);
    const monitoredPrompt = monitoredRunArgs.at(-1);
    assert.match(monitoredPrompt, /audit-live-001/);
    assert.match(monitoredPrompt, new RegExp(canonicalRepositoryRoot.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.match(monitoredPrompt, /源码根目录必须只读/);
    assert.match(monitoredPrompt, /唯一的持久交付根目录/);
    assert.equal(monitoredPrompt.includes(reportsRoot), true);
    assert.equal(monitoredPrompt.includes(join(reportsRoot, "final", `security-audit-report.${created.id}.md`)), true);
    assert.match(monitoredPrompt, /120 秒快速动态确认/);
    assert.match(monitoredPrompt, /完整动态验证仍只允许用户在工作台手动点击/);
    assert.match(monitoredPrompt, /不得调用 question 工具/);
    assert.match(monitoredPrompt, /additional-instructions\.txt/);
    assert.match(monitoredPrompt, /test-environment\.txt/);
    assert.equal(monitoredPrompt.includes("context-attacker-secret"), false);
    assert.equal(spawnCall.options.env.AUDIT_QUICK_DYNAMIC_ENABLED, "true");
    assert.equal(spawnCall.options.env.AUDIT_QUICK_DYNAMIC_DEADLINE_SECONDS, "120");
    assert.equal(spawnCall.options.env.AUDIT_FULL_DYNAMIC_TRIGGER, "MANUAL_ONLY");
    assert.equal(spawnCall.options.env.http_proxy, "http://proxy-fixture.test:8080");
    assert.equal(spawnCall.options.env.HTTPS_PROXY, "http://secure-proxy-fixture.test:8443");
    assert.equal(terminalMonitor.starts[0].environment.http_proxy, "http://proxy-fixture.test:8080");
    assert.equal(terminalMonitor.starts[0].environment.HTTPS_PROXY, "http://secure-proxy-fixture.test:8443");
    assert.match(spawnCall.options.env.AUDIT_TEST_ENVIRONMENT_CONTEXT_SHA256, /^[a-f0-9]{64}$/);
    const additionalContextPath = join(stateRoot, created.id, "additional-instructions.txt");
    const testEnvironmentContextPath = join(stateRoot, created.id, "test-environment.txt");
    assert.match(await readFile(additionalContextPath, "utf8"), /只验证 XSS 漏洞/);
    assert.match(await readFile(testEnvironmentContextPath, "utf8"), /context-attacker-secret/);
    assert.equal((await stat(additionalContextPath)).mode & 0o077, 0);
    assert.equal((await stat(testEnvironmentContextPath)).mode & 0o077, 0);
    const originalEnvironmentContext = await readFile(testEnvironmentContextPath);
    await writeFile(testEnvironmentContextPath, "tampered-context\n", "utf8");
    assert.equal((await runner.dynamicValidationPolicy(created.id, "fixture")).enabled, false);
    await writeFile(testEnvironmentContextPath, originalEnvironmentContext);
    assert.equal((await runner.dynamicValidationPolicy(created.id, "fixture")).enabled, true);
    const persistedAuditState = await readFile(join(stateRoot, created.id, "run.json"), "utf8");
    assert.equal(persistedAuditState.includes("context-attacker-secret"), false);
    assert.equal(persistedAuditState.includes("context-victim-secret"), false);
    assert.equal(persistedAuditState.includes("proxy-fixture.test"), false);
    const proxyEnvironmentPath = join(stateRoot, created.id, "proxy-environment.json");
    assert.match(await readFile(proxyEnvironmentPath, "utf8"), /proxy-fixture\.test/);
    assert.equal((await stat(proxyEnvironmentPath)).mode & 0o077, 0);
    assert.equal(spawnCall.options.env.AUDIT_SOURCE_ROOT, canonicalRepositoryRoot);
    assert.equal(spawnCall.options.env.AUDIT_WORKSPACE_ROOT, executionWorkspace);
    assert.equal(spawnCall.options.env.AUDIT_REPORTS_ROOT, reportsRoot);
    assert.equal(spawnCall.options.env.AUDIT_TMP_ROOT, join(platformRoot, "tmp", "repositories", "fixture"));
    assert.equal(terminalMonitor.starts[0].executionDirectory, executionWorkspace);
    await assert.rejects(stat(join(executionWorkspace, "source")), error => error.code === "ENOENT");
    assert.equal(await realpath(join(executionWorkspace, "reports")), await realpath(reportsRoot));
    assert.equal(await realpath(join(executionWorkspace, "tmp")), await realpath(join(platformRoot, "tmp", "repositories", "fixture")));
    await assert.rejects(stat(join(canonicalRepositoryRoot, "reports")), error => error.code === "ENOENT");
    await assert.rejects(stat(join(canonicalRepositoryRoot, "tmp")), error => error.code === "ENOENT");
    assert.equal(runner.getAudit(created.id).execution_transport, "opencode-run+terminal-multiplexer");
    assert.equal(runner.getAudit(created.id).terminal.live, true);

    const activeDeleteResponse = await fetch(`${base}/api/v1/audits/${created.id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", "If-Match": `"${runner.getAudit(created.id).version}"` },
      body: JSON.stringify({ confirmation: created.id }),
    });
    assert.equal(activeDeleteResponse.status, 409);
    assert.equal((await activeDeleteResponse.json()).error, "audit-delete-active");

    terminalMonitor.output += "\ncontext-attacker-secret";
    const terminalResponse = await fetch(`${base}/api/v1/audits/${created.id}/terminal`);
    assert.equal(terminalResponse.status, 200);
    const terminalPayload = await terminalResponse.json();
    assert.equal(terminalPayload.live, true);
    assert.equal(terminalPayload.target, "audit:tui");
    assert.match(terminalPayload.output, /OpenCode TUI fixture/);
    assert.equal(terminalPayload.output.includes("context-attacker-secret"), false);
    assert.match(terminalPayload.output, /PRIVATE_CONTEXT_REDACTED/);
    assert.match(terminalPayload.attach_command, /^tmux -L owa-/);
    assert.match(terminalPayload.attach_command, /attach-session -r -t audit:tui$/);
    assert.equal(terminalPayload.provider_session_id, `ses_${created.id}`);
    assert.equal(terminalPayload.opencode_command, `opencode -s ses_${created.id}`);
    const resizeResponse = await fetch(`${base}/api/v1/audits/${created.id}/terminal/resize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ columns: 164, rows: 40 }),
    });
    assert.equal(resizeResponse.status, 200);
    const resizedTerminal = await resizeResponse.json();
    assert.equal(resizedTerminal.columns, 164);
    assert.equal(resizedTerminal.rows, 40);
    assert.deepEqual(terminalMonitor.resizeCalls.map(({ columns, rows }) => ({ columns, rows })), [{ columns: 164, rows: 40 }]);
    const invalidResizeResponse = await fetch(`${base}/api/v1/audits/${created.id}/terminal/resize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ columns: 9999, rows: 1 }),
    });
    assert.equal(invalidResizeResponse.status, 422);
    assert.equal((await invalidResizeResponse.json()).error, "terminal-size-invalid");

    child.stdout.write('{"type":"agent.progress","token":"must-not-leak"}\n');
    child.stdout.write('{"type":"agent.progress","message":"context-attacker-secret"}\n');
    for (let attempt = 0; attempt < 20 && (await runner.eventsSince(created.id)).length < 4; attempt += 1) await new Promise(resolve => setImmediate(resolve));
    const events = await runner.eventsSince(created.id);
    assert.equal(events.some(event => JSON.stringify(event).includes("must-not-leak")), false);
    assert.equal(events.some(event => JSON.stringify(event).includes("context-attacker-secret")), false);
    assert.deepEqual(events.map(event => event.sequence), events.map((_, index) => index + 1));
    const logResponse = await fetch(`${base}/api/v1/audits/${created.id}/logs?limit=20`);
    assert.equal(logResponse.status, 200);
    const logPayload = JSON.stringify(await logResponse.json());
    assert.equal(logPayload.includes("must-not-leak"), false);
    assert.equal(logPayload.includes("context-attacker-secret"), false);
    assert.match(logPayload, /PRIVATE_CONTEXT_REDACTED/);

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
    assert.equal(requestList.items[0].dispatch_ready, false);
    assert.equal(requestList.items[0].task_dynamic_validation_enabled, false);
    assert.equal(requestList.items[0].artifact_dispatch_ready, true);

    const disabledValidationResponse = await fetch(`${base}/api/v1/validations`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "dynamic-disabled" },
      body: JSON.stringify({
        validation_request_id: "web-xss-fixture::FIND-WEB-XSS-001",
        repository_id: "fixture",
        target_base_url: "http://127.0.0.1:8080/profile",
        attacker_account: { username: "attacker", password: "secret-a" },
        victim_account: { username: "victim", password: "secret-b" },
        login_instructions: "测试登录。",
        cleanup_instructions: "删除测试数据。",
        explicit_authorization: true,
        test_environment: true,
      }),
    });
    assert.equal(disabledValidationResponse.status, 409);
    assert.equal((await disabledValidationResponse.json()).error, "audit-dynamic-validation-disabled");
    assert.equal(dynamicSpawnCall, null);

    const enabledValidationAuditRoot = join(runtimeRoot, created.id);
    await mkdir(enabledValidationAuditRoot, { recursive: true });
    const enabledValidationRequest = buildWebXssRuntimeRequest(fixtureCommit, { auditId: created.id });
    const enabledRequestPath = join(enabledValidationAuditRoot, "request.json");
    const enabledRequestBytes = `${JSON.stringify(enabledValidationRequest, null, 2)}\n`;
    await writeFile(enabledRequestPath, enabledRequestBytes, "utf8");
    const enabledValidationEnvelope = buildWebXssInputEnvelope({ request: enabledValidationRequest, requestPath: enabledRequestPath, requestBytes: enabledRequestBytes });
    await writeFile(join(enabledValidationAuditRoot, "envelope-input.json"), `${JSON.stringify(enabledValidationEnvelope, null, 2)}\n`, "utf8");
    const enabledValidationRequestId = `${created.id}::FIND-WEB-XSS-001`;
    const enabledRequestList = await (await fetch(`${base}/api/v1/validation-requests`)).json();
    const enabledDescriptor = enabledRequestList.items.find(item => item.id === enabledValidationRequestId);
    assert.equal(enabledRequestList.count, 2);
    assert.equal(enabledDescriptor.dispatch_ready, true);
    assert.equal(enabledDescriptor.task_dynamic_validation_enabled, true);

    const remoteValidationResponse = await fetch(`${base}/api/v1/validations`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "dynamic-remote" },
      body: JSON.stringify({
        validation_request_id: enabledValidationRequestId,
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
        validation_request_id: enabledValidationRequestId,
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
    assert.equal(validationResponse.status, 202, JSON.stringify(await validationResponse.clone().json()));
    const startedValidation = await validationResponse.clone().json();
    const dynamicJobId = startedValidation.id;
    assert.equal(startedValidation.idempotency_digest, undefined);
    assert.match(dynamicJobId, /^[a-f0-9]{24}$/);
    assert.notEqual(dynamicJobId, enabledValidationRequestId);
    for (let attempt = 0; attempt < 100 && dynamicRunner.getRun(dynamicJobId)?.status !== "running"; attempt += 1) await new Promise(resolve => setTimeout(resolve, 2));
    assert.equal(dynamicRunner.getRun(dynamicJobId).status, "running");
    const activeValidationRequests = await (await fetch(`${base}/api/v1/validation-requests`)).json();
    const activeValidationDescriptor = activeValidationRequests.items.find(item => item.id === enabledValidationRequestId);
    assert.equal(activeValidationDescriptor.job_id, dynamicJobId);
    assert.equal(activeValidationDescriptor.job.id, dynamicJobId);
    assert.equal(dynamicSpawnCall.command, "opencode");
    assert.equal(dynamicSpawnCall.options.shell, false);
    assert.equal(dynamicSpawnCall.args[4], "dynamic-vulnerability-validator");
    const dynamicExecutionWorkspace = join(platformRoot, "workspace", "audit-runs", created.id);
    assert.equal(dynamicSpawnCall.options.cwd, dynamicExecutionWorkspace);
    assert.equal(dynamicSpawnCall.args[dynamicSpawnCall.args.indexOf("--dir") + 1], dynamicExecutionWorkspace);
    assert.equal(dynamicSpawnCall.options.env.AUDIT_SOURCE_ROOT, canonicalRepositoryRoot);
    assert.equal(dynamicSpawnCall.options.env.AUDIT_REPORTS_ROOT, reportsRoot);
    assert.notEqual(dynamicSpawnCall.options.env.XDG_DATA_HOME, process.env.XDG_DATA_HOME);
    assert.equal(JSON.stringify(dynamicSpawnCall.args).includes("attacker-secret-value"), false);
    assert.equal(JSON.stringify(dynamicSpawnCall.args).includes("victim-secret-value"), false);
    const authorizationFile = dynamicSpawnCall.args[dynamicSpawnCall.args.indexOf("--file") + 1];
    assert.match(await readFile(authorizationFile, "utf8"), /attacker-secret-value/);
    assert.equal((await stat(authorizationFile)).mode & 0o077, 0);
    dynamicChild.stdout.write('{"password":"attacker-secret-value","token":"victim-secret-value"}\n');
    await writeFile(join(enabledValidationAuditRoot, "FIND-WEB-XSS-001.result.json"), "{}\n", "utf8");
    dynamicChild.emit("close", 0, null);
    for (let attempt = 0; attempt < 60 && dynamicRunner.getRun(dynamicJobId)?.ephemeral_cleanup !== "SUCCEEDED"; attempt += 1) await new Promise(resolve => setImmediate(resolve));
    assert.equal(dynamicRunner.getRun(dynamicJobId).status, "completed");
    assert.equal(dynamicRunner.getRun(dynamicJobId).ephemeral_cleanup, "SUCCEEDED");
    assert.equal(dynamicRunner.getRun(dynamicJobId).result_validation, "PASSED");
    const dynamicLog = await readFile(join(dynamicRunner.directory(dynamicJobId), "runner.log.jsonl"), "utf8");
    assert.equal(dynamicLog.includes("attacker-secret-value"), false);
    assert.equal(dynamicLog.includes("victim-secret-value"), false);
    await assert.rejects(stat(resolve(dynamicSpawnCall.options.env.XDG_DATA_HOME, "..")), error => error.code === "ENOENT");
    const validationRunsResponse = await fetch(`${base}/api/runs`);
    assert.equal(validationRunsResponse.status, 200);
    const validationRuns = await validationRunsResponse.json();
    assert.equal(validationRuns.count, 1);
    assert.match(validationRuns.runs[0].resource_id, /^[a-f0-9]{24}$/);
    assert.equal(validationRuns.runs[0].repository_id, "fixture");
    const validationDetailResponse = await fetch(`${base}/api/runs/${validationRuns.runs[0].resource_id}`);
    assert.equal(validationDetailResponse.status, 200);
    const validationDetail = await validationDetailResponse.json();
    assert.equal(validationDetail.run.repository_id, "fixture");
    assert.equal(validationDetail.run.id, enabledValidationRequestId);
    await assert.rejects(stat(join(canonicalRepositoryRoot, "reports")), error => error.code === "ENOENT");
    await assert.rejects(stat(join(canonicalRepositoryRoot, "tmp")), error => error.code === "ENOENT");
    assert.equal((await runner.listRepositories())[0].dirty, false);

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
    assert.equal(terminalMonitor.signals.at(-1), "SIGSTOP");

    const paused = runner.getAudit(created.id);
    const resumeResponse = await fetch(`${base}/api/v1/audits/${created.id}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": `"${paused.version}"`, "Idempotency-Key": "resume-001" },
      body: JSON.stringify({ action: "resume" }),
    });
    assert.equal(resumeResponse.status, 202);
    assert.equal(child.signals.at(-1), "SIGCONT");
    assert.equal(terminalMonitor.signals.at(-1), "SIGCONT");

    const resumed = runner.getAudit(created.id);
    const cancelResponse = await fetch(`${base}/api/v1/audits/${created.id}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": `"${resumed.version}"`, "Idempotency-Key": "cancel-001" },
      body: JSON.stringify({ action: "cancel" }),
    });
    assert.equal(cancelResponse.status, 202);
    assert.equal(child.signals.at(-1), "SIGTERM");
    assert.equal(terminalMonitor.abortCalls.length, 1);
    for (let attempt = 0; attempt < 50 && runner.getAudit(created.id)?.status !== "cancelled"; attempt += 1) await new Promise(resolve => setImmediate(resolve));
    assert.equal(runner.getAudit(created.id).status, "cancelled");
    assert.equal(runner.getAudit(created.id).terminal.status, "archived");
    assert.equal(terminalMonitor.stopCalls, 1);
    const archivedTerminal = await (await fetch(`${base}/api/v1/audits/${created.id}/terminal`)).json();
    assert.equal(archivedTerminal.live, false);
    assert.equal(archivedTerminal.available, true);
    assert.equal(archivedTerminal.attach_command, null);
    assert.equal(archivedTerminal.provider_session_id, `ses_${created.id}`);
    assert.equal(archivedTerminal.opencode_command, `opencode -s ses_${created.id}`);
    assert.match(archivedTerminal.output, /security-audit-orchestrator is running/);

    const auditTmpRoot = join(platformRoot, "tmp", "repositories", "fixture", created.id);
    const ownedArtifact = join(reportsRoot, "coverage", `coverage-summary.${created.id}.json`);
    const unrelatedArtifact = join(reportsRoot, "coverage", "coverage-summary.audit-keep.json");
    await mkdir(auditTmpRoot, { recursive: true });
    await writeFile(join(auditTmpRoot, "scanner-output.json"), "{}\n", "utf8");
    await writeFile(ownedArtifact, `${JSON.stringify({ audit_id: created.id, coverage_status: "INCOMPLETE" })}\n`, "utf8");
    await writeFile(unrelatedArtifact, `${JSON.stringify({ audit_id: "audit-keep", coverage_status: "INCOMPLETE" })}\n`, "utf8");
    const cancelledAudit = runner.getAudit(created.id);
    const invalidDeleteResponse = await fetch(`${base}/api/v1/audits/${created.id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", "If-Match": `"${cancelledAudit.version}"` },
      body: JSON.stringify({ confirmation: "wrong-audit-id" }),
    });
    assert.equal(invalidDeleteResponse.status, 422);
    const deleteResponse = await fetch(`${base}/api/v1/audits/${created.id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", "If-Match": `"${cancelledAudit.version}"` },
      body: JSON.stringify({ confirmation: created.id }),
    });
    assert.equal(deleteResponse.status, 200, JSON.stringify(await deleteResponse.clone().json()));
    const deletedAudit = await deleteResponse.json();
    assert.equal(deletedAudit.deleted, true);
    assert.equal(deletedAudit.removed_artifact_files, 4);
    assert.equal(deletedAudit.removed_runner_state, true);
    assert.equal(runner.getAudit(created.id), null);
    await assert.rejects(stat(join(stateRoot, created.id)), error => error.code === "ENOENT");
    await assert.rejects(stat(executionWorkspace), error => error.code === "ENOENT");
    await assert.rejects(stat(auditTmpRoot), error => error.code === "ENOENT");
    await assert.rejects(stat(ownedArtifact), error => error.code === "ENOENT");
    assert.equal((await stat(unrelatedArtifact)).isFile(), true);
    assert.equal((await fetch(`${base}/api/v1/audits/${created.id}`)).status, 404);

    const artifactOnlyAudit = (await (await fetch(`${base}/api/v1/workspace`)).json()).audits.find(item => item.id === "audit-history");
    const artifactOnlyDeleteResponse = await fetch(`${base}/api/v1/audits/audit-history`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", "If-Match": `"${artifactOnlyAudit.version}"` },
      body: JSON.stringify({ confirmation: "audit-history" }),
    });
    assert.equal(artifactOnlyDeleteResponse.status, 200, JSON.stringify(await artifactOnlyDeleteResponse.clone().json()));
    const artifactOnlyDeletion = await artifactOnlyDeleteResponse.json();
    assert.equal(artifactOnlyDeletion.removed_runner_state, false);
    assert.equal(artifactOnlyDeletion.removed_artifact_files, 4);
    assert.equal(artifactOnlyDeletion.removed_finding_workflows, 1);
    await assert.rejects(stat(findingWorkflow.directory(findingResourceId)), error => error.code === "ENOENT");
    assert.equal((await stat(join(reportsRoot, "final", "security-audit-report.audit-sealed.md"))).isFile(), true);

    const queueDefaultsResponse = await fetch(`${base}/api/v1/settings/queue`);
    assert.equal(queueDefaultsResponse.status, 200);
    assert.deepEqual((await queueDefaultsResponse.json()).queue.enabled, false);
    const queueInvalidResponse = await fetch(`${base}/api/v1/settings/queue`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interval_hours: 0 }),
    });
    assert.equal(queueInvalidResponse.status, 422);
    const queueUpdateResponse = await fetch(`${base}/api/v1/settings/queue`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interval_hours: 0.5, concurrency: 2 }),
    });
    assert.equal(queueUpdateResponse.status, 200);
    assert.equal((await queueUpdateResponse.json()).queue.interval_hours, 0.5);
    const queueActivateResponse = await fetch(`${base}/api/v1/settings/queue/activate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    assert.equal(queueActivateResponse.status, 200);
    assert.equal((await queueActivateResponse.json()).queue.enabled, true);
    const queuedAuditResponse = await fetch(`${base}/api/v1/audits`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "queue-audit-request" },
      body: JSON.stringify({
        audit_id: "audit-queued-001",
        repository_id: "fixture",
        ref: "HEAD",
        allow_dirty: true,
      }),
    });
    assert.equal(queuedAuditResponse.status, 202);
    const queuedAudit = await queuedAuditResponse.json();
    assert.equal(queuedAudit.status, "queued");
    assert.equal(runner.getAudit(queuedAudit.id).status, "queued");
    assert.equal((await (await fetch(`${base}/api/v1/workspace`)).json()).queue.queued_count, 1);
    const queuedDispatchResponse = await fetch(`${base}/api/v1/audits/${queuedAudit.id}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": `"${runner.getAudit(queuedAudit.id).version}"`, "Idempotency-Key": "queue-audit-dispatch" },
      body: JSON.stringify({ action: "dispatch" }),
    });
    assert.equal(queuedDispatchResponse.status, 202, JSON.stringify(await queuedDispatchResponse.clone().json()));
    assert.equal((await queuedDispatchResponse.json()).status, "running");
    assert.equal(runner.getAudit(queuedAudit.id).status, "running");
    const queuedCancelResponse = await fetch(`${base}/api/v1/audits/${queuedAudit.id}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": `"${runner.getAudit(queuedAudit.id).version}"`, "Idempotency-Key": "queue-audit-cancel" },
      body: JSON.stringify({ action: "cancel" }),
    });
    assert.equal(queuedCancelResponse.status, 202);
    for (let attempt = 0; attempt < 50 && runner.getAudit(queuedAudit.id)?.status !== "cancelled"; attempt += 1) await new Promise(resolve => setImmediate(resolve));
    assert.equal(runner.getAudit(queuedAudit.id).status, "cancelled");
    const queuedDeleteResponse = await fetch(`${base}/api/v1/audits/${queuedAudit.id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", "If-Match": `"${runner.getAudit(queuedAudit.id).version}"` },
      body: JSON.stringify({ confirmation: queuedAudit.id }),
    });
    assert.equal(queuedDeleteResponse.status, 200);
    assert.equal(runner.getAudit(queuedAudit.id), null);
    const queuedFifoAuditResponse = await fetch(`${base}/api/v1/audits`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "queue-audit-fifo-request" },
      body: JSON.stringify({ audit_id: "audit-queued-002", repository_id: "fixture", ref: "HEAD", allow_dirty: true }),
    });
    assert.equal(queuedFifoAuditResponse.status, 202);
    const queuedFifoAudit = await queuedFifoAuditResponse.json();
    assert.equal(queuedFifoAudit.status, "queued");
    const queueDispatchResponse = await fetch(`${base}/api/v1/settings/queue/dispatch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    assert.equal(queueDispatchResponse.status, 202, JSON.stringify(await queueDispatchResponse.clone().json()));
    assert.equal((await queueDispatchResponse.json()).queue.queued_count, 0);
    assert.equal(runner.getAudit(queuedFifoAudit.id).status, "running");
    const queuedFifoCancelResponse = await fetch(`${base}/api/v1/audits/${queuedFifoAudit.id}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": `"${runner.getAudit(queuedFifoAudit.id).version}"`, "Idempotency-Key": "queue-audit-fifo-cancel" },
      body: JSON.stringify({ action: "cancel" }),
    });
    assert.equal(queuedFifoCancelResponse.status, 202);
    for (let attempt = 0; attempt < 50 && runner.getAudit(queuedFifoAudit.id)?.status !== "cancelled"; attempt += 1) await new Promise(resolve => setImmediate(resolve));
    assert.equal(runner.getAudit(queuedFifoAudit.id).status, "cancelled");
    const queuedFifoDeleteResponse = await fetch(`${base}/api/v1/audits/${queuedFifoAudit.id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", "If-Match": `"${runner.getAudit(queuedFifoAudit.id).version}"` },
      body: JSON.stringify({ confirmation: queuedFifoAudit.id }),
    });
    assert.equal(queuedFifoDeleteResponse.status, 200);
    const queueDeactivateResponse = await fetch(`${base}/api/v1/settings/queue/deactivate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    assert.equal(queueDeactivateResponse.status, 200);
    assert.equal((await queueDeactivateResponse.json()).queue.enabled, false);

    const indexResponse = await fetch(`${base}/`);
    assert.equal(indexResponse.status, 200);
    const indexHtml = await indexResponse.text();
    assert.match(indexHtml, /DeepHole·JAVA/);
    assert.match(indexHtml, /id="report-dialog"/);
    assert.match(indexHtml, /class="report-preview markdown-body"/);
    assert.match(indexHtml, /id="finding-dialog"/);
    assert.match(indexHtml, /id="terminal-dialog"/);
    assert.match(indexHtml, /data-view="settings"/);
    assert.match(indexHtml, /id="queue-settings-form"/);
    assert.match(indexHtml, /队列间隔/);
    assert.match(indexHtml, /激活排队机制/);
    assert.match(indexHtml, /id="opencode-session-id"/);
    assert.match(indexHtml, />OpenCode 会话直连</);
    assert.match(indexHtml, /id="delete-audit-dialog"/);
    assert.match(indexHtml, />确认删除</);
    assert.match(indexHtml, /name="additional_instructions_enabled"/);
    assert.match(indexHtml, /name="additional_instructions"/);
    assert.match(indexHtml, /name="test_environment_enabled"/);
    assert.match(indexHtml, /name="test_environment_context"/);
    assert.match(indexHtml, /未启用时不会启动浏览器/);
    assert.match(indexHtml, /全任务最多 120 秒/);
    assert.match(indexHtml, /完整动态验证仍需在验证页逐次手动触发/);
    assert.doesNotMatch(indexHtml, /输入完整 audit_id/);
    assert.doesNotMatch(indexHtml, /<script(?![^>]+src=)[^>]*>/i);
    const appResponse = await fetch(`${base}/app.js`);
    const stylesResponse = await fetch(`${base}/styles.css`);
    assert.equal(appResponse.status, 200);
    assert.equal(stylesResponse.status, 200);
    const appSource = await appResponse.text();
    const stylesSource = await stylesResponse.text();
    assert.match(appSource, /npm --prefix \.opencode run start:audit-workbench:runner/);
    assert.match(appSource, /runner-log-line/);
    assert.match(appSource, /output\.scrollTop = output\.scrollHeight/);
    assert.match(stylesSource, /runner-log-line\.historical/);
    assert.match(stylesSource, /runner-log-line\.recent/);
    assert.match(appSource, /删除任务/);
    assert.match(appSource, /断点恢复/);
    assert.match(appSource, /ResizeObserver/);
    assert.match(appSource, /terminal\/resize/);
    assert.match(appSource, /syncAuditContextControls/);
    assert.match(appSource, /task_dynamic_validation_enabled/);
    assert.match(appSource, /progress_source/);
    assert.match(appSource, /排队中/);
    assert.match(appSource, /立即调度/);
    assert.match(appSource, /立即开始/);
    assert.match(indexHtml, /立即调度队列/);
    assert.match(appSource, /\/api\/v1\/settings\/queue/);
    assert.match(appSource, /markdown-it-html-disabled/);
    assert.match(appSource, /关联 Repo/);
    assert.match(appSource, /finding\.repository_name/);
    assert.doesNotMatch(appSource, /window\.confirm/);
    const referencedIds = [...appSource.matchAll(/\$\("([A-Za-z0-9_-]+)"\)/g)].map(match => match[1]);
    assert.deepEqual([...new Set(referencedIds)].filter(id => !indexHtml.includes(`id="${id}"`)), []);
    assert.match(stylesSource, /@media \(max-width: 1080px\)/);
    assert.match(stylesSource, /@media \(max-width: 760px\)/);
  } finally {
    server.close();
    await once(server, "close");
  }

  assert.throws(() => parseArgs(["--host", "0.0.0.0"]), /loopback/);
  assert.throws(() => parseArgs(["--repo", "bad-format"]), /id=\/absolute\/path/);
  assert.throws(() => parseArgs(["--repo", "fixture=relative/path"]), /id=\/absolute\/path/);
  assert.equal(parseArgs([]).repositories.length, 0);
  const options = parseArgs(["--enable-runner", "--enable-dynamic-validation", "--repo", `fixture=${repositoryRoot}`, "--port", "0"]);
  assert.equal(options.runnerEnabled, true);
  assert.equal(options.dynamicRunnerEnabled, true);
  assert.equal(options.repositories[0].id, "fixture");
  const reloadedRunner = new AuditRunner({ stateRoot, platformRoot, configPath: join(repositoryRoot, ".opencode", "opencode.json") });
  await reloadedRunner.ready;
  assert.equal(reloadedRunner.runtimeRepositories().some(repository => repository.path === canonicalOperatorSelectedRoot), true);

  const resumableStateRoot = join(temp, "resumable-audit-state");
  const resumableAuditId = "audit-resume-001";
  const resumableAuditDirectory = join(resumableStateRoot, resumableAuditId);
  const resumableWorkspace = join(platformRoot, "workspace", "audit-runs", resumableAuditId);
  await mkdir(resumableAuditDirectory, { recursive: true });
  const resumedProxyEnvironment = { http_proxy: "http://resume-proxy-fixture.test:8080", HTTPS_PROXY: "http://resume-secure-proxy-fixture.test:8443" };
  const resumedProxyDocument = `${JSON.stringify({ schema_version: 1, environment: resumedProxyEnvironment }, null, 2)}\n`;
  await writeFile(join(resumableAuditDirectory, "proxy-environment.json"), resumedProxyDocument, { encoding: "utf8", mode: 0o600 });
  await writeFile(join(resumableAuditDirectory, "run.json"), `${JSON.stringify({
    id: resumableAuditId,
    name: "中断恢复测试",
    repository_id: "fixture",
    repository_name: "测试仓库",
    commit: fixtureCommit,
    branch: "main",
    status: "running",
    version: 3,
    event_sequence: 0,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    started_at: new Date().toISOString(),
    finished_at: null,
    exit_code: null,
    error: null,
    allow_dirty: false,
    provider_session_id: "ses_resume_fixture",
    recovery_count: 0,
    private_runtime: {
      proxy_environment: {
        enabled: true,
        file_name: "proxy-environment.json",
        sha256: createHash("sha256").update(resumedProxyDocument).digest("hex"),
        variable_names: Object.keys(resumedProxyEnvironment).sort(),
      },
    },
    paths: {
      source_root: canonicalRepositoryRoot,
      workspace_root: resumableWorkspace,
      reports_root: reportsRoot,
      tmp_root: join(platformRoot, "tmp", "repositories", "fixture"),
    },
    terminal: {
      backend: "tmux",
      supported: true,
      status: "ready",
      live: true,
      socket_name: "owa-0123456789abcdef",
      target: "audit:tui",
      server_url: "http://127.0.0.1:41234",
      provider_session_id: "ses_resume_fixture",
    },
  }, null, 2)}\n`, "utf8");
  const resumeTerminalMonitor = new FakeTerminalMonitor();
  const resumedChild = new FakeChild();
  let resumedSpawnCall = null;
  const resumableRunner = new AuditRunner({
    stateRoot: resumableStateRoot,
    platformRoot,
    repositories: [{ id: "fixture", name: "测试仓库", path: repositoryRoot }],
    configPath: join(repositoryRoot, ".opencode", "opencode.json"),
    enabled: true,
    environment: { PATH: process.env.PATH ?? "" },
    terminalMonitor: resumeTerminalMonitor,
    spawnProcess(command, args, options) {
      resumedSpawnCall = { command, args, options };
      return resumedChild;
    },
  });
  await resumableRunner.ready;
  const interruptedAudit = resumableRunner.getAudit(resumableAuditId);
  assert.equal(interruptedAudit.status, "interrupted");
  assert.equal(interruptedAudit.interruption_reason, "workbench-restarted");
  assert.equal(interruptedAudit.terminal.live, true);
  assert.equal(resumeTerminalMonitor.stopCalls, 0, "服务重载不应擅自终止仍可查看的精确 tmux 会话");
  const resumedAudit = await resumableRunner.action(resumableAuditId, "recover", interruptedAudit.version, "resume-action-001");
  assert.equal(resumedAudit.status, "running");
  assert.equal(resumedAudit.recovery_count, 1);
  assert.equal(resumedAudit.provider_session_id, "ses_resume_fixture");
  assert.equal(resumeTerminalMonitor.abortCalls.length, 1);
  assert.equal(resumeTerminalMonitor.starts[0].providerSessionId, "ses_resume_fixture");
  assert.equal(resumeTerminalMonitor.starts[0].environment.http_proxy, resumedProxyEnvironment.http_proxy);
  assert.equal(resumeTerminalMonitor.starts[0].environment.HTTPS_PROXY, resumedProxyEnvironment.HTTPS_PROXY);
  assert.equal(resumedSpawnCall.command, process.execPath);
  assert.match(resumedSpawnCall.args[0], /terminal-output-relay\.mjs$/);
  assert.equal(resumedSpawnCall.options.env.http_proxy, resumedProxyEnvironment.http_proxy);
  assert.equal(resumedSpawnCall.options.env.HTTPS_PROXY, resumedProxyEnvironment.HTTPS_PROXY);
  assert.equal(JSON.stringify(resumedAudit).includes("resume-proxy-fixture.test"), false);
  const resumeRunArgs = resumeTerminalMonitor.starts[0].args;
  assert.equal(resumeRunArgs[resumeRunArgs.indexOf("--session") + 1], "ses_resume_fixture");
  assert.match(resumeRunArgs.at(-1), /第 1 次断点恢复/);
  assert.match(resumeRunArgs.at(-1), /不得删除有效制品/);
  assert.match(resumeRunArgs.at(-1), /不得调用 question 工具/);
  const duplicateResume = await resumableRunner.action(resumableAuditId, "recover", interruptedAudit.version, "resume-action-001");
  assert.equal(duplicateResume.status, "running");
  assert.equal(resumeTerminalMonitor.starts.length, 1, "同一幂等键不得重复启动恢复 Runner");
  resumedChild.emit("close", 0, null);
  for (let attempt = 0; attempt < 50 && resumableRunner.getAudit(resumableAuditId)?.status !== "completed"; attempt += 1) await new Promise(resolve => setImmediate(resolve));
  assert.equal(resumableRunner.getAudit(resumableAuditId).status, "completed");
  await resumableRunner.shutdown();

  const legacyWatchdogStateRoot = join(temp, "legacy-watchdog-state");
  const legacyWatchdogReportsRoot = join(temp, "legacy-watchdog-reports");
  const legacyWatchdogId = "audit-legacy-watchdog";
  const legacyWatchdogDirectory = join(legacyWatchdogStateRoot, legacyWatchdogId);
  for (const directory of ["coverage", "vulnerability-mining", "correlation", "adjudication", "validation", "final"]) {
    await mkdir(join(legacyWatchdogReportsRoot, directory), { recursive: true });
  }
  await writeFile(join(legacyWatchdogReportsRoot, "coverage", `coverage-plan.${legacyWatchdogId}.json`), JSON.stringify({ audit_id: legacyWatchdogId }), "utf8");
  for (const directory of ["vulnerability-mining", "correlation", "adjudication", "validation"]) {
    await writeFile(join(legacyWatchdogReportsRoot, directory, `${directory}.${legacyWatchdogId}.json`), JSON.stringify({ audit_id: legacyWatchdogId }), "utf8");
  }
  await writeFile(join(legacyWatchdogReportsRoot, "final", `security-audit-report.${legacyWatchdogId}.md`), "# 历史审计报告\n", "utf8");
  await mkdir(legacyWatchdogDirectory, { recursive: true });
  await writeFile(join(legacyWatchdogDirectory, "run.json"), `${JSON.stringify({
    id: legacyWatchdogId,
    name: "历史任务完成性 watchdog 测试",
    repository_id: "fixture",
    repository_name: "测试仓库",
    commit: fixtureCommit,
    branch: "main",
    status: "interrupted",
    version: 2,
    event_sequence: 0,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    finished_at: new Date().toISOString(),
    exit_code: null,
    error: "workbench restarted",
    allow_dirty: false,
    paths: { source_root: canonicalRepositoryRoot, workspace_root: join(platformRoot, "workspace", "audit-runs", legacyWatchdogId), reports_root: legacyWatchdogReportsRoot, tmp_root: join(platformRoot, "tmp", "repositories", "fixture") },
    terminal: { backend: "tmux", supported: true, status: "disconnected", live: true, socket_name: "owa-legacy-watchdog", target: "audit:tui" },
  }, null, 2)}\n`, "utf8");
  const legacyWatchdogTerminal = new FakeTerminalMonitor();
  let legacyWatchdogSpawned = false;
  const legacyWatchdogRunner = new AuditRunner({
    stateRoot: legacyWatchdogStateRoot,
    platformRoot,
    repositories: [{ id: "fixture", name: "测试仓库", path: repositoryRoot }],
    configPath: join(repositoryRoot, ".opencode", "opencode.json"),
    enabled: true,
    terminalMonitor: legacyWatchdogTerminal,
    spawnProcess() { legacyWatchdogSpawned = true; return new FakeChild(); },
  });
  await legacyWatchdogRunner.ready;
  const watchdogCompletedAudit = legacyWatchdogRunner.getAudit(legacyWatchdogId);
  assert.equal(watchdogCompletedAudit.status, "completed");
  assert.equal(watchdogCompletedAudit.completion_source, "legacy-artifact-heuristic");
  assert.equal(watchdogCompletedAudit.error, null);
  assert.equal(legacyWatchdogTerminal.abortCalls.length, 1);
  assert.equal(legacyWatchdogTerminal.stopCalls, 1);
  await assert.rejects(
    legacyWatchdogRunner.action(legacyWatchdogId, "recover", watchdogCompletedAudit.version, "legacy-watchdog-recover"),
    error => error.code === "audit-not-recoverable",
  );
  assert.equal(legacyWatchdogSpawned, false);
  await legacyWatchdogRunner.shutdown();

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

  const reloadedFindingWorkflow = new FindingWorkflowStore({ stateRoot: findingWorkflowRoot });
  await reloadedFindingWorkflow.ready;
  const deletedWorkflow = reloadedFindingWorkflow.get(findingResourceId);
  assert.equal(deletedWorkflow.status, "unreviewed");
  assert.equal(deletedWorkflow.version, 0);

  process.stdout.write(`${JSON.stringify({ complete: true, service: "opencode-audit-workbench", cases: tmuxInstalled ? 201 : 196 })}\n`);
} finally {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      await rm(temp, { recursive: true, force: true });
      break;
    } catch (error) {
      if (error?.code !== "ENOTEMPTY" || attempt === 4) throw error;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
  }
}
