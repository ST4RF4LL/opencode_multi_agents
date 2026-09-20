#!/usr/bin/env node
import { strict as assert } from "node:assert";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import http from "node:http";
import { PassThrough, Readable } from "node:stream";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { PROTOCOL, authorize, selection, seal, digest, validatePacket, validateSubmission } from "../lib/runtime-testing/contract.mjs";
import { RuntimeTestingController } from "../lib/runtime-testing/controller.mjs";
import { RuntimeTestingService } from "../lib/runtime-testing/service.mjs";
import { ChromeRuntimeBrowser, authorizedConnectTarget, targetLookup, createOriginProxy } from "../lib/runtime-testing/browser.mjs";
import { verifyRuntimeEvidenceFiles, runtimeCandidates } from "../lib/runtime-testing/evidence.mjs";
import { runtimeStageRegistry } from "../lib/runtime-testing/stage-registry.mjs";
import { reportArtifactPath } from "../lib/runtime-testing/paths.mjs";
import { verifyIntegratedFinalReport } from "../lib/runtime-testing/final-verification.mjs";
import { finalReportModelDigest } from "../skills/common-subagent/audit-coverage-accounting/scripts/final-report-model-core.mjs";
import { validateStageContractRegistry } from "../skills/common-subagent/audit-artifact-management/scripts/stage-agent-contract.mjs";
import { validateStageDeliveryRegistry } from "../skills/common-subagent/audit-artifact-management/scripts/stage-delivery-contract.mjs";
import { validateTruthValidationBundle, validateStaticRoleReview, validateTruthValidationIntake } from "../skills/vulnerability-validator-subagent/vulnerability-validation/scripts/truth-validation-contract.mjs";

const portableMacOS = process.platform === "darwin" && process.env.AUDIT_ALLOW_MACOS_PORTABLE_TESTS === "1";
if (!["linux", "win32"].includes(process.platform) && !portableMacOS) throw new Error("请在 Windows/Linux 执行回归；经授权的 macOS 伪浏览器回归可设置 AUDIT_ALLOW_MACOS_PORTABLE_TESTS=1。真实运行平台限制保持不变。");
const SHA = "a".repeat(64);
const selected = selection({ runtime_testing: { protocol: PROTOCOL, mode: "INTEGRATED_TESTING", budget_minutes: 60, explicit_authorization: true, identity_mode: "anonymous", allowed_actions: ["navigate", "normal_interaction", "test_input"] } });
function grant(overrides = {}) { return authorize({ auditId: "audit-runtime-test", selected, enabled: true, context: JSON.stringify({ url: "http://127.0.0.1:8080", revision: "fixture-1" }), scopeDigest: SHA, ...overrides }); }
function packet(authorization, phase = "CONTACT", id = "contact-1", extra = {}) {
  return { protocol: PROTOCOL, audit_id: authorization.audit_id, id, phase, authorization_digest: authorization.artifact_digest,
    environment_revision: authorization.environment_revision, identity_ids: authorization.identities.map(identity => identity.id),
    budget_seconds: 600, actions: ["navigate"], question: "边界是否按预期工作？", expected_behavior: "正常输入得到预期响应。", steps: ["检查授权测试页面。"], counterchecks: ["与正常输入对照。"],
    ...(["EXPLORE", "CONFIRM"].includes(phase) ? { hypothesis_id: `hypothesis-${id}`, focus_area_id: "focus-fixture", scope_digest: SHA, vulnerability_type_id: "JW-ACCESS-01" } : {}),
    ...(phase === "CONFIRM" ? { finding_id: "finding-1", finding_object_digest: SHA } : {}), ...extra };
}
function submission(extra = {}) { return { execution_status: "COMPLETED", outcome: "NOT_OBSERVED", cleanup_status: "NOT_REQUIRED", summary: "已完成授权基线检查。", observations: ["普通请求符合预期。"], evidence_ids: [], changes: [], gaps: [], ...extra }; }
async function temporary(t) { const root = await mkdtemp(join(tmpdir(), "runtime-testing-")); t.after(() => rm(root, { recursive: true, force: true })); return root; }
function fakeBrowser(counts) {
  return { tools: async () => [{ name: "navigate_page", inputSchema: { type: "object" } }],
    call: async (_name, args) => { counts.calls++; return { content: [{ type: "text", text: `正常页面 ${args.identity_id}` }] }; },
    close: async () => { counts.closed++; } };
}
async function successfulWorker({ controller, active }) {
  const evidence = [];
  for (const identity_id of active.packet.identity_ids) evidence.push((await controller.call(active.token, "navigate_page", { identity_id, url: "http://127.0.0.1:8080" })).evidence_id);
  await controller.submit(active.token, submission({ evidence_ids: evidence }));
}

test("空环境及旧 opt-in 不启动控制服务、worker 或浏览器", async t => {
  assert.equal(selection({ test_environment_enabled: true }), null);
  const root = await temporary(t); let calls = 0;
  for (const [index, context] of [undefined, null, "", "   \r\n", {}].entries()) {
    const authorization = grant({ context }); assert.equal(authorization.public.status, "SKIPPED");
    const service = new RuntimeTestingService({ root: join(root, `reports-${index}`), privateRoot: join(root, `private-${index}`), authorization: authorization.public,
      browserFactory: async () => { calls++; throw new Error("不得启动浏览器"); }, worker: async () => { calls++; } });
    await service.start(); assert.equal(service.server, null); await service.contact();
    assert.equal((await service.controller.run({})).status, "SKIPPED");
    const evidence = await verifyRuntimeEvidenceFiles(join(root, `reports-${index}`, "evidence-set.json"));
    assert.equal(evidence.packets.length, 0); await service.shutdown();
  }
  assert.equal(calls, 0);
  assert.equal(grant({ selected: null }).public.reason, "DYNAMIC_NOT_AUTHORIZED");
  assert.equal(grant({ enabled: false }).public.status, "SKIPPED");
});

test("非法目标、缺少身份和缺少持久化清理范围均自动跳过", () => {
  for (const url of ["file:///tmp/index.html", "ftp://test.example", "http://user:pass@localhost:8080", "http://host:99999", "http://host/a b", "http://host\\other"]) assert.equal(grant({ context: JSON.stringify({ url }) }).public.status, "SKIPPED");
  for (const context of ["{}", "null", "[]", "无法解析的环境", JSON.stringify({ url: "http://localhost:8080", origins: ["http://localhost:8081"] })]) assert.equal(grant({ context }).public.status, "SKIPPED");
  assert.equal(grant({ selected: { ...selected, identity_mode: "distinct" } }).public.reason, "REQUIRED_IDENTITIES_MISSING");
  assert.equal(grant({ selected: { ...selected, allowed_actions: [...selected.allowed_actions, "test_mutation"] } }).public.reason, "REQUIRED_MUTATION_SCOPE_MISSING");
  assert.equal(grant({ context: JSON.stringify({ url: "http://localhost:8080", requires_login: true }) }).public.status, "SKIPPED");
  const first = grant(); const second = grant({ context: JSON.stringify({ url: "http://127.0.0.1:8080", revision: "fixture-2" }) });
  assert.notEqual(first.public.artifact_digest, second.public.artifact_digest);
});

test("测试环境按用户授权接受任意网络地址，兼容中文字段和无协议地址", () => {
  const cases = [
    ["地址：192.0.2.10:31943，用户说明见下文", "http://192.0.2.10:31943/"],
    ["192.0.2.10:31943", "http://192.0.2.10:31943/"],
    ["URL: https://test.example:8443/app", "https://test.example:8443/app"],
    ["地址：http://10.0.0.8:8080", "http://10.0.0.8:8080/"],
    ["地址：test.internal:8080", "http://test.internal:8080/"],
    ["URL: http://service:8080", "http://service:8080/"],
    ["地址：[2001:db8::1]:8080", "http://[2001:db8::1]:8080/"],
    ["[::1]:8080", "http://[::1]:8080/"],
    ["localhost:8080", "http://localhost:8080/"],
    ["- **URL**: `http://test.example:8080`", "http://test.example:8080/"],
    ["入口 http://test.example:8080，登录 http://test.example:8080/login", "http://test.example:8080/"],
    ["URL: http://test.example:8080\n登录：http://test.example:8080/login\n参考：https://docs.example/guide", "http://test.example:8080/"],
    [JSON.stringify({ target_base_url: "test.example:8080" }), "http://test.example:8080/"],
  ];
  for (const [context, url] of cases) {
    const auth = grant({ context }); assert.equal(auth.public.status, "AUTHORIZED", context);
    assert.equal(auth.private.url, url); assert.deepEqual(auth.public.origins, [new URL(url).origin]);
  }
  const auth = grant({ context: JSON.stringify({ url: "https://test.example/app", origins: ["https://test.example", "https://login.test.example"] }) });
  assert.equal(auth.public.status, "AUTHORIZED"); assert.deepEqual(auth.public.origins, ["https://login.test.example", "https://test.example"]);
  assert.equal(grant({ enabled: false, context: cases[0][0] }).public.reason, "DYNAMIC_NOT_AUTHORIZED");
  assert.equal(grant({ selected: { ...selected, explicit_authorization: false }, context: cases[0][0] }).public.reason, "DYNAMIC_NOT_AUTHORIZED");
});

test("远程目标仍校验身份并保持账号私有，解析失败展示具体原因", () => {
  const context = "地址：192.0.2.10:31943\n测试账号：fixture-user\n测试密码：fixture-password";
  const auth = grant({ selected: { ...selected, identity_mode: "shared" }, context });
  assert.equal(auth.public.status, "AUTHORIZED");
  assert.deepEqual(auth.private.accounts, [{ id: "shared", username: "fixture-user", password: "fixture-password" }]);
  assert.doesNotMatch(JSON.stringify(auth.public), /fixture-user|fixture-password/);
  assert.equal(grant({ context }).public.reason, "IDENTITY_SCOPE_MISMATCH");
  assert.equal(grant({ selected: { ...selected, identity_mode: "shared" }, context: "地址：192.0.2.10:31943\n用户：fixture-user" }).public.reason, "REQUIRED_IDENTITIES_MISSING");
  assert.equal(grant({ selected: { ...selected, identity_mode: "shared" }, context: "地址：192.0.2.10:31943\n用户：\n密码：fixture-password" }).public.reason, "REQUIRED_IDENTITIES_MISSING");
  const cases = [
    ["没有地址", "ENVIRONMENT_URL_MISSING"],
    ["URL: http://test.example:99999", "ENVIRONMENT_URL_INVALID"],
    ["地址：无效地址\n说明：http://test.example", "ENVIRONMENT_URL_INVALID"],
    ['{"url":"http://test.example",', "ENVIRONMENT_FORMAT_INVALID"],
    ["[]", "ENVIRONMENT_FORMAT_INVALID"],
    ["首页：http://test.example\n登录：https://login.test.example", "ENVIRONMENT_URL_AMBIGUOUS"],
    [JSON.stringify({ url: "http://test.example", origins: ["http://other.example"] }), "ENVIRONMENT_ORIGINS_INVALID"],
    [JSON.stringify({ url: "http://test.example", origins: ["http://test.example/path"] }), "ENVIRONMENT_ORIGINS_INVALID"],
  ];
  for (const [value, reason] of cases) {
    const result = grant({ context: value }); assert.equal(result.public.status, "SKIPPED");
    assert.equal(result.public.reason, reason, value); assert.equal(result.private, null);
    assert.deepEqual(result.public.origins, []);
  }
});

test("阶段契约按显式协议分流，旧注册表保持原摘要", async () => {
  const agentPath = new URL("../skills/common-subagent/audit-artifact-management/contracts/stage-agent-contracts.json", import.meta.url);
  const deliveryPath = new URL("../skills/common-subagent/audit-artifact-management/contracts/workbench-stage-deliveries.json", import.meta.url);
  const agents = JSON.parse(await readFile(agentPath, "utf8")); const deliveries = JSON.parse(await readFile(deliveryPath, "utf8"));
  const original = JSON.stringify([agents, deliveries]);
  assert.equal(runtimeStageRegistry(agents, ""), agents);
  const nextAgents = runtimeStageRegistry(agents, PROTOCOL); const nextDeliveries = runtimeStageRegistry(deliveries, PROTOCOL);
  assert.deepEqual(validateStageContractRegistry(nextAgents), []);
  assert.deepEqual(validateStageDeliveryRegistry(nextDeliveries, nextAgents), []);
  assert.equal(nextAgents.contracts.some(row => row.agent_name === "quick-dynamic-validator"), false);
  assert.ok(nextAgents.contracts.find(row => row.agent_name === "vulnerability-validator").output.required_artifact_types.includes("runtime-testing-evidence-set"));
  assert.equal(JSON.stringify([agents, deliveries]), original);
});

test("工作包不能扩展授权、范围或借 CONTACT 进行探索", () => {
  const authorization = grant().public;
  for (const extra of [{ actions: ["test_input"] }, { identity_ids: ["victim"] }, { environment_revision: "changed" }, { authorization_digest: SHA }]) assert.throws(() => validatePacket(packet(authorization, "CONTACT", "contact", extra), authorization));
  assert.throws(() => validatePacket(packet(authorization, "EXPLORE", "explore", { scope_digest: "b".repeat(64) }), authorization));
  assert.throws(() => validatePacket(packet(authorization, "CONFIRM", "confirm", { finding_object_digest: null }), authorization));
});

test("测试数据变更不能标为无需清理，中期 XSS 支持也必须提供应用证据", () => {
  const authorization = grant().public; const plan = packet(authorization, "EXPLORE", "explore-xss", { vulnerability_type_id: "JW-INJECT-06" });
  const result = submission({ outcome: "SUPPORTED", evidence_ids: ["action-1"] });
  assert.throws(() => validateSubmission(result, plan, new Set(["action-1"])), /xss-application-proof-required/);
  const regular = packet(authorization, "EXPLORE", "explore-regular");
  assert.throws(() => validateSubmission(submission({ changes: [{ marker: "unique-marker", resource: "授权测试记录", cleanup_status: "SUCCEEDED" }] }), regular, new Set()), /cleanup-summary-mismatch/);
  assert.throws(() => validateSubmission(submission({ changes: [{ marker: "unique-marker", resource: "授权测试记录", cleanup_status: "NOT_REQUIRED" }] }), regular, new Set()), /change-ledger-required/);
});

test("XSS 支持需要两个身份的实际工具记录，脱敏保留固定 proof.method", async t => {
  const root = await temporary(t); const auth = grant({ selected: { ...selected, identity_mode: "distinct" }, context: JSON.stringify({ url: "http://127.0.0.1:8080", accounts: [
    { id: "attacker", username: "REAL", password: "fixture-password-a" }, { id: "victim", username: "victim-test", password: "fixture-password-b" },
  ] }) });
  const counts = { calls: 0, closed: 0 };
  const controller = new RuntimeTestingController({ root, authorization: auth.public, privateContext: auth.private, browserFactory: async () => fakeBrowser(counts), worker: successfulWorker });
  try {
    await controller.run(packet(auth.public));
    const active = await controller.start(packet(auth.public, "EXPLORE", "explore-xss", { vulnerability_type_id: "JW-INJECT-06" }));
    const first = await controller.call(active.token, "navigate_page", { identity_id: "attacker", url: auth.private.url });
    const result = submission({ outcome: "SUPPORTED", evidence_ids: [first.evidence_id], proof: {
      method: "REAL_APPLICATION_INPUT", persisted_or_revisited: "通过真实应用输入后重访测试页面。", victim_execution: "独立授权身份观察唯一测试标记。",
    } });
    await assert.rejects(controller.submit(active.token, result), /xss-identities-not-observed/);
    const second = await controller.call(active.token, "take_snapshot", { identity_id: "victim" }); result.evidence_ids.push(second.evidence_id);
    await controller.submit(active.token, result); await controller.finish(active, active.submission); await controller.close();
    const evidence = await verifyRuntimeEvidenceFiles(join(root, "evidence-set.json"));
    assert.equal(evidence.packets[1].result.proof.method, "REAL_APPLICATION_INPUT");
  } finally { await controller.cancel(); }
});

test("Web 注入的报告绝对目录与工作区 reports 别名均可解析，越界路径拒绝", async t => {
  const root = await temporary(t); const prior = process.env.AUDIT_REPORTS_ROOT;
  try {
    process.env.AUDIT_REPORTS_ROOT = join(root, "durable", "repo"); const workspace = join(root, "workspace", "audit");
    const actual = join(process.env.AUDIT_REPORTS_ROOT, "runtime-testing", "audit-one", "evidence-set.json");
    assert.deepEqual(reportArtifactPath(workspace, actual), { absolute: actual, relative: "reports/runtime-testing/audit-one/evidence-set.json" });
    assert.equal(reportArtifactPath(workspace, "reports/validation/intake.json").relative, "reports/validation/intake.json");
    assert.throws(() => reportArtifactPath(workspace, join(root, "durable", "other", "secret.json")), /路径不在/);
    assert.throws(() => reportArtifactPath(workspace, actual, "reports/validation/"), /路径不在/);
  } finally { if (prior === undefined) delete process.env.AUDIT_REPORTS_ROOT; else process.env.AUDIT_REPORTS_ROOT = prior; }
});

test("同一环境串行复用浏览器，身份基线和实际证据必须齐备", async t => {
  const root = await temporary(t); const auth = grant(); const counts = { calls: 0, closed: 0, factories: 0 };
  const controller = new RuntimeTestingController({ root, authorization: auth.public, browserFactory: async () => { counts.factories++; return fakeBrowser(counts); }, worker: successfulWorker });
  await controller.ready;
  await assert.rejects(controller.start(packet(auth.public, "EXPLORE", "premature")), /baseline/);
  const active = await controller.start(packet(auth.public));
  await assert.rejects(controller.start(packet(auth.public, "CONTACT", "duplicate")), /busy/);
  await assert.rejects(controller.submit(active.token, submission()), /evidence-required/);
  await successfulWorker({ controller, active }); await controller.finish(active, active.submission);
  await assert.rejects(controller.call(active.token, "navigate_page", { identity_id: "anonymous" }), /lease-invalid/);
  await controller.run(packet(auth.public, "EXPLORE", "explore-1"));
  assert.equal(counts.factories, 1); assert.equal(counts.calls, 2);
  await controller.close(); assert.equal(counts.closed, 1);
  const evidence = await verifyRuntimeEvidenceFiles(join(root, "evidence-set.json")); assert.equal(evidence.packets.length, 2);
  await writeFile(join(root, evidence.evidence_bindings[0].path), "{}");
  await assert.rejects(verifyRuntimeEvidenceFiles(join(root, "evidence-set.json")), /evidence-changed/);
});

test("跨审计与 loopback 别名不能并发占用同一环境", async t => {
  const root = await temporary(t); const services = [];
  try {
  for (const [index, host] of ["127.0.0.1", "localhost"].entries()) {
    const auth = grant({ auditId: `audit-lock-${index}`, context: JSON.stringify({ url: `http://${host}:8080` }) });
    const service = new RuntimeTestingService({ root: join(root, `reports-${index}`), privateRoot: join(root, "state", `audit-${index}`, "runtime-testing"), authorization: auth.public,
      worker: async () => { throw new Error("此用例不应启动 worker"); } }); services.push(service); await service.start();
  }
  assert.notEqual(services[0].server, null); assert.equal(services[1].server, null);
  assert.equal(services[1].controller.state.reason, "ENVIRONMENT_ALREADY_LEASED");
  } finally { for (const service of services) await service.shutdown(); }
});

test("不同远程主机同端口不互锁，同一授权目标仍互斥且不启动浏览器", async t => {
  const root = await temporary(t); const services = []; let browserCalls = 0;
  try {
    for (const [index, host] of ["192.0.2.10", "198.51.100.10", "localhost", "192.0.2.10"].entries()) {
      const auth = grant({ auditId: `audit-remote-lock-${index}`, context: JSON.stringify({ url: `http://${host}:8080` }) });
      const service = new RuntimeTestingService({ root: join(root, `reports-${index}`), privateRoot: join(root, "state", `audit-${index}`, "runtime-testing"), authorization: auth.public,
        browserFactory: async () => { browserCalls++; throw new Error("不得启动浏览器"); } });
      services.push(service); await service.start();
    }
    for (const service of services.slice(0, 3)) assert.notEqual(service.server, null);
    assert.equal(services[3].server, null); assert.equal(services[3].controller.state.reason, "ENVIRONMENT_ALREADY_LEASED");
    assert.equal(browserCalls, 0);
  } finally { for (const service of services) await service.shutdown(); }
});

test("服务启动通知失败会关闭 API 并释放未使用的环境租约", async t => {
  const root = await temporary(t); const auth = grant();
  const failed = new RuntimeTestingService({ root: join(root, "failed"), privateRoot: join(root, "state", "failed", "runtime-testing"),
    authorization: auth.public, onChange: async () => { throw new Error("fixture-notification-failed"); } });
  await assert.rejects(failed.start(), /fixture-notification-failed/);
  assert.equal(failed.server, null);
  const next = new RuntimeTestingService({ root: join(root, "next"), privateRoot: join(root, "state", "next", "runtime-testing"), authorization: auth.public });
  try { await next.start(); assert.notEqual(next.server, null); } finally { await next.shutdown(); }
});

test("出队后准入前关闭服务，工作包在封存前记 SKIPPED 且不会迟到改写", async t => {
  const root = await temporary(t); const auth = grant(); let release; let entered; let workers = 0;
  const gate = new Promise(resolve => { release = resolve; }); const started = new Promise(resolve => { entered = resolve; });
  const service = new RuntimeTestingService({ root: join(root, "reports"), privateRoot: join(root, "state", "audit", "runtime-testing"),
    authorization: auth.public, worker: async () => { workers++; } });
  await service.start();
  const admit = service.controller.start.bind(service.controller);
  service.controller.start = async value => { entered(); await gate; return admit(value); };
  try {
    await service.enqueue(packet(auth.public)); await started;
    await service.shutdown();
    const before = await readFile(join(root, "reports", "evidence-set.json"), "utf8");
    release(); await service.draining;
    const evidence = await verifyRuntimeEvidenceFiles(join(root, "reports", "evidence-set.json"));
    assert.equal(evidence.packets.length, 1); assert.equal(evidence.packets[0].execution_status, "SKIPPED");
    assert.equal(JSON.stringify(service.controller.state.packets), JSON.stringify(evidence.packets.map(({ evidence_validity, ...row }) => row)));
    assert.equal(await readFile(join(root, "reports", "evidence-set.json"), "utf8"), before); assert.equal(workers, 0);
  } finally { release(); await service.shutdown(); }
});

for (const [index, failure] of ["BLOCKED", "FAILED"].entries()) test(`${failure} 自动封存并跳过未执行队列，CLI close 可供静态收尾`, async t => {
  const root = await temporary(t); const auth = grant({ context: JSON.stringify({ url: `http://127.0.0.1:${19090 + index}` }) });
  let entered; let release; const started = new Promise(resolve => { entered = resolve; }); const gate = new Promise(resolve => { release = resolve; });
  const reports = join(root, "reports"); const privateRoot = join(root, "state", "audit", "runtime-testing");
  const service = new RuntimeTestingService({ root: reports, privateRoot, authorization: auth.public, worker: async ({ controller, active }) => {
    entered(); await gate;
    if (failure === "FAILED") throw new Error("fixture-worker-failed");
    await controller.submit(active.token, submission({ execution_status: "BLOCKED", outcome: "INCONCLUSIVE", gaps: ["测试登录步骤不可用。"] }));
  } });
  try {
    await service.start(); await service.contact(); await started;
    await service.enqueue(packet(auth.public, "EXPLORE", "pending-explore")); release(); await service.draining;
    const evidence = await verifyRuntimeEvidenceFiles(join(reports, "evidence-set.json"));
    assert.equal(evidence.status, failure === "BLOCKED" ? "BLOCKED" : "QUARANTINED");
    assert.equal(evidence.packets.length, 2); assert.equal(evidence.packets[1].execution_status, "SKIPPED");
    assert.equal(evidence.packets[1].reason, "ENVIRONMENT_UNAVAILABLE"); assert.equal(service.controller.closed, true);
    const cli = fileURLToPath(new URL("../scripts/runtime-testing.mjs", import.meta.url));
    const { stdout } = await promisify(execFile)(process.execPath, [cli, "close"], { timeout: 5000, env: { ...process.env,
      AUDIT_RUNTIME_PROTOCOL: PROTOCOL, AUDIT_RUNTIME_STATE_ROOT: reports, AUDIT_RUNTIME_CONNECTION_PATH: join(privateRoot, "endpoint.json") } });
    assert.equal(JSON.parse(stdout).status, evidence.status);
  } finally { release(); await service.shutdown(); }
});

test("证据汇总不能更改工作包的 finding、阶段或实际证据归属", async t => {
  const root = await temporary(t); const auth = grant(); const counts = { calls: 0, closed: 0 };
  const controller = new RuntimeTestingController({ root, authorization: auth.public, browserFactory: async () => fakeBrowser(counts), worker: successfulWorker });
  await controller.run(packet(auth.public)); await controller.run(packet(auth.public, "CONFIRM", "confirm-1"));
  const evidence = await controller.close(); const path = join(root, "evidence-set.json");
  await verifyRuntimeEvidenceFiles(path);
  for (const [field, value] of [["finding_id", "another-finding"], ["phase", "EXPLORE"], ["scope_digest", "b".repeat(64)]]) {
    const changed = structuredClone(evidence); changed.packets[1][field] = value;
    await writeFile(path, JSON.stringify(seal(changed)));
    await assert.rejects(verifyRuntimeEvidenceFiles(path), /input-binding-invalid/);
  }
  const changed = structuredClone(evidence); changed.packets[1].evidence_ids = evidence.packets[0].evidence_ids;
  await writeFile(path, JSON.stringify(seal(changed)));
  await assert.rejects(verifyRuntimeEvidenceFiles(path), /evidence-invalid/);
});

test("受控 MCP 接受已授权远程导航，拒绝其他目标和任意脚本，各身份独立", async () => {
  const auth = grant({ selected: { ...selected, identity_mode: "distinct" }, context: JSON.stringify({ url: "http://test.example:8080", accounts: [
    { id: "attacker", username: "test-a", password: "private-a" }, { id: "victim", username: "test-v", password: "private-v" },
  ] }) });
  const created = []; const calls = []; const closed = [];
  const browser = new ChromeRuntimeBrowser(auth.public, { clientFactory: async id => {
    created.push(id); return { listTools: async () => ({ tools: [{ name: "navigate_page", inputSchema: { type: "object", properties: { url: { type: "string" } } } }, { name: "evaluate_script", inputSchema: {} }] }),
      callTool: async request => { calls.push({ id, request }); return { content: [] }; }, close: async () => closed.push(id) };
  } });
  try {
    const plan = packet(auth.public);
    await assert.rejects(browser.call("navigate_page", { identity_id: "attacker", url: "http://test.example:8081" }, plan), /origin-not-authorized/);
    await assert.rejects(browser.call("navigate_page", { identity_id: "attacker", url: "http://127.0.0.1:8081" }, plan), /origin-not-authorized/);
    await assert.rejects(browser.call("navigate_page", { identity_id: "attacker", url: "https://example.com" }, plan), /origin-not-authorized/);
    await assert.rejects(browser.call("evaluate_script", { identity_id: "attacker", function: "() => 1" }, plan), /tool-not-authorized/);
    assert.deepEqual(created, []);
    const available = await browser.tools(plan); assert.equal(available.some(tool => tool.name === "evaluate_script"), false);
    for (const id of ["attacker", "victim", "attacker"]) await browser.call("navigate_page", { identity_id: id, url: "http://test.example:8080" }, plan);
    assert.deepEqual(created, ["attacker", "victim"]); assert.equal(calls.length, 3);
  } finally { await browser.close(); }
  assert.deepEqual(closed.sort(), ["attacker", "victim"]);
});

test("HTTPS 默认端口和 IPv6 CONNECT 正确匹配，非法 authority 不接触目标", () => {
  const origins = ["https://localhost", "https://127.0.0.1:8443", "https://[::1]", "https://test.example", "https://192.0.2.10:8443", "https://[2001:db8::1]:8443"];
  assert.deepEqual(authorizedConnectTarget("localhost:443", origins), { host: "127.0.0.1", port: 443 });
  assert.deepEqual(authorizedConnectTarget("[::1]:443", origins), { host: "::1", port: 443 });
  assert.deepEqual(authorizedConnectTarget("127.0.0.1:8443", origins), { host: "127.0.0.1", port: 8443 });
  assert.deepEqual(authorizedConnectTarget("test.example:443", origins), { host: "test.example", port: 443 });
  assert.deepEqual(authorizedConnectTarget("192.0.2.10:8443", origins), { host: "192.0.2.10", port: 8443 });
  assert.deepEqual(authorizedConnectTarget("[2001:db8::1]:8443", origins), { host: "2001:db8::1", port: 8443 });
  for (const authority of ["localhost:444", "localhost:443/path", "localhost:443#fragment", "user@localhost:443", "example.com:443", "localhost", "127.1:443"]) assert.equal(authorizedConnectTarget(authority, origins), null);
});

test("只有 localhost 固定到本机，远程 IP 保持实际地址且不发 DNS 请求", async () => {
  targetLookup("localhost", { all: true }, (error, addresses) => { assert.equal(error, null); assert.deepEqual(addresses, [{ address: "127.0.0.1", family: 4 }]); });
  targetLookup("localhost", {}, (error, address, family) => { assert.equal(error, null); assert.equal(address, "127.0.0.1"); assert.equal(family, 4); });
  await new Promise((resolve, reject) => targetLookup("192.0.2.10", { all: true }, (error, addresses) => {
    if (error) return reject(error);
    try { assert.deepEqual(addresses, [{ address: "192.0.2.10", family: 4 }]); resolve(); } catch (failure) { reject(failure); }
  }));
});

test("HTTP 代理能访问本用例的授权伪服务，其他 origin 被拒绝", async () => {
  let received = 0;
  const target = http.createServer((_request, response) => { received++; response.end("fixture-response"); });
  await new Promise((resolve, reject) => { target.once("error", reject); target.listen(0, "127.0.0.1", resolve); });
  const origin = `http://localhost:${target.address().port}`; let proxy;
  try {
    proxy = await createOriginProxy([origin]);
    const request = path => new Promise((resolve, reject) => {
      const pending = http.request(proxy.url, { method: "GET", path, agent: false }, response => {
        const chunks = []; response.on("data", chunk => chunks.push(chunk)); response.on("end", () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
      });
      pending.on("error", reject); pending.setTimeout(2000, () => pending.destroy(new Error("fixture-timeout"))); pending.end();
    });
    assert.deepEqual(await request(`${origin}/fixture`), { status: 200, body: "fixture-response" });
    assert.equal((await request("http://example.com/forbidden")).status, 403);
    assert.equal(received, 1);
  } finally {
    await proxy?.close(); target.closeAllConnections(); await new Promise(resolve => target.close(resolve));
  }
});

test("HTTP 代理向授权远程地址转发且拒绝其他 origin；上游使用替身", async t => {
  const originalRequest = http.request; const forwarded = [];
  t.mock.method(http, "request", (url, options, receive) => {
    forwarded.push({ url, options });
    const upstream = new PassThrough();
    upstream.on("finish", () => {
      const reply = Readable.from(["fixture-response"]); reply.statusCode = 200; reply.headers = {};
      receive(reply);
    });
    return upstream;
  });
  const origin = "http://192.0.2.10:31943";
  const proxy = await createOriginProxy([origin]);
  const request = path => new Promise((resolve, reject) => {
    const pending = originalRequest(proxy.url, { path, headers: { "proxy-authorization": "fixture-secret" } }, response => {
      let body = ""; response.setEncoding("utf8"); response.on("data", chunk => { body += chunk; });
      response.on("end", () => resolve({ status: response.statusCode, body }));
    });
    pending.on("error", reject); pending.end();
  });
  try {
    assert.deepEqual(await request(`${origin}/login`), { status: 200, body: "fixture-response" });
    for (const other of ["http://192.0.2.10:31944", "http://198.51.100.10:31943", "http://localhost:31943"]) assert.equal((await request(other)).status, 403);
    assert.equal(forwarded.length, 1); assert.equal(forwarded[0].url.href, `${origin}/login`);
    assert.equal(forwarded[0].options.headers.host, "192.0.2.10:31943");
    assert.equal(forwarded[0].options.headers["proxy-authorization"], undefined);
    assert.equal(forwarded[0].options.lookup, targetLookup);
  } finally { await proxy.close(); }
});

test("并发工具发现只初始化一次身份，关闭后迟到的 client 不再连接", async () => {
  const auth = grant(); let created = 0; let closed = 0; let listed = 0; let release; let started;
  const gate = new Promise(resolve => { release = resolve; }); const entered = new Promise(resolve => { started = resolve; });
  const browser = new ChromeRuntimeBrowser(auth.public, { clientFactory: async () => {
    created++; started(); await gate;
    return { listTools: async () => { listed++; return { tools: [] }; }, close: async () => { closed++; } };
  } });
  const pending = Promise.allSettled([browser.tools(packet(auth.public)), browser.tools(packet(auth.public))]);
  try {
    await entered; assert.equal(created, 1); await browser.close(); release();
    assert.ok((await pending).every(result => result.status === "rejected"));
    assert.equal(listed, 0); assert.equal(closed, 1);
  } finally { release(); await browser.close(); await pending; }
});

test("控制器取消后迟到的 browser factory 必须关闭且不能执行工具", async t => {
  const root = await temporary(t); const auth = grant(); let release; let started; let closed = 0; let listed = 0;
  const gate = new Promise(resolve => { release = resolve; }); const entered = new Promise(resolve => { started = resolve; });
  const controller = new RuntimeTestingController({ root, authorization: auth.public, browserFactory: async () => {
    started(); await gate; return { tools: async () => { listed++; return []; }, close: async () => { closed++; } };
  } });
  const active = await controller.start(packet(auth.public)); const pending = controller.tools(active.token);
  const rejected = assert.rejects(pending, /lease-invalid/);
  await entered; await controller.cancel(); release(); await rejected;
  assert.equal(controller.browser, null); assert.equal(listed, 0); assert.equal(closed, 1);
});

test("初始化期间取消阻止尚未准入的工作包和浏览器启动", async t => {
  const root = await temporary(t); const auth = grant(); let workers = 0;
  const controller = new RuntimeTestingController({ root, authorization: auth.public, worker: async () => { workers++; } });
  const pending = assert.rejects(controller.run(packet(auth.public)), /unavailable/);
  await controller.cancel(); await pending;
  assert.equal(workers, 0); assert.equal(controller.state.packets.length, 0); assert.equal(controller.state.status, "CLOSED");
});

test("取消使挂起的 worker 退出控制器等待并保持唯一 CANCELLED 结果", async t => {
  const root = await temporary(t); const auth = grant(); let entered; let stopped = 0;
  const started = new Promise(resolve => { entered = resolve; });
  const controller = new RuntimeTestingController({ root, authorization: auth.public, worker: async ({ active }) => {
    active.stopWorker = () => { stopped++; }; entered(); await new Promise(() => {});
  } });
  const pending = controller.run(packet(auth.public)); await started; await controller.cancel();
  let timer;
  try {
    const state = await Promise.race([pending, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("cancel-waited-for-worker")), 2000); })]);
    assert.equal(state.packets.length, 1); assert.equal(state.packets[0].execution_status, "CANCELLED");
    assert.equal(stopped, 1);
  } finally { clearTimeout(timer); }
});

test("清理失败保留支持证据并隔离环境，后续测试不能继续", async t => {
  const root = await temporary(t); const auth = grant(); const counts = { calls: 0, closed: 0 };
  const controller = new RuntimeTestingController({ root, authorization: auth.public, browserFactory: async () => fakeBrowser(counts), worker: successfulWorker });
  await controller.run(packet(auth.public));
  controller.worker = async ({ controller, active }) => {
    const evidence = await controller.call(active.token, "navigate_page", { identity_id: "anonymous", url: "http://127.0.0.1:8080" });
    await controller.submit(active.token, submission({ outcome: "SUPPORTED", evidence_ids: [evidence.evidence_id], cleanup_status: "FAILED", gaps: ["测试记录仍需人工清理。"],
      changes: [{ marker: "unique-test-marker", resource: "授权测试记录", cleanup_status: "FAILED" }] }));
  };
  await controller.run(packet(auth.public, "EXPLORE", "explore-1"));
  assert.equal(controller.state.status, "QUARANTINED");
  await assert.rejects(controller.run(packet(auth.public, "EXPLORE", "explore-2")), /unavailable/);
  const evidence = await controller.close(); assert.equal(evidence.packets[1].outcome, "SUPPORTED"); assert.equal(evidence.cleanup_status, "FAILED");
  assert.equal(runtimeCandidates(evidence).length, 1);
});

test("真实计时包含 worker 等待，超时撤销租约且不接收迟到结果", async t => {
  const root = await temporary(t); const auth = grant(); let active; let time = 0; let stopped = 0;
  const controller = new RuntimeTestingController({ root, authorization: auth.public, now: () => time,
    setTimer: callback => setTimeout(() => { time += 10_001; callback(); }, 5),
    worker: async args => { active = args.active; active.stopWorker = () => { stopped++; }; await new Promise(() => {}); } });
  const state = await controller.run(packet(auth.public, "CONTACT", "contact-1", { budget_seconds: 10 }));
  assert.equal(state.status, "QUARANTINED"); assert.equal(state.packets[0].execution_status, "TIMED_OUT"); assert.equal(state.elapsed_ms, 10_001); assert.equal(stopped, 1);
  await assert.rejects(controller.submit(active.token, submission()), /lease-invalid/);
  await controller.close();
});

test("已接收结果立即结束计时，不依赖 worker 自愿退出", async t => {
  const root = await temporary(t); const auth = grant(); const counts = { calls: 0, closed: 0 }; let stopped = 0; let watchdog;
  const controller = new RuntimeTestingController({ root, authorization: auth.public, browserFactory: async () => fakeBrowser(counts),
    setTimer: callback => { watchdog = callback; return 1; }, clearTimer: () => {},
    worker: async ({ controller, active }) => {
      active.stopWorker = () => { stopped++; };
      await successfulWorker({ controller, active });
      await new Promise(() => {});
    } });
  let timer;
  try {
    const result = await Promise.race([controller.run(packet(auth.public)), new Promise((_, reject) => {
      timer = setTimeout(() => { watchdog?.(); reject(new Error("accepted-result-waited-for-worker")); }, 2000);
    })]);
    assert.equal(result.packets[0].execution_status, "COMPLETED"); assert.equal(result.status, "READY"); assert.equal(stopped, 1);
  } finally { clearTimeout(timer); await controller.close(); }
});

test("进程恢复不继承未知环境，已耗预算与历史保留", async t => {
  const root = await temporary(t); const auth = grant();
  const first = new RuntimeTestingController({ root, authorization: auth.public }); await first.ready; await first.start(packet(auth.public));
  const recovered = new RuntimeTestingController({ root, authorization: auth.public }); await recovered.ready;
  assert.equal(recovered.state.status, "QUARANTINED"); assert.equal(recovered.state.packets[0].execution_status, "FAILED");
  await assert.rejects(recovered.run(packet(auth.public, "CONTACT", "retry")), /unavailable/);
  const different = new RuntimeTestingController({ root, authorization: seal({ ...auth.public, environment_revision: "changed" }) });
  await assert.rejects(different.ready, /new-run-required/);
});

test("恢复后未执行队列逐项记 SKIPPED，并能封存证据供静态收尾", async t => {
  const root = await temporary(t); const auth = grant();
  const first = new RuntimeTestingController({ root, authorization: auth.public }); await first.ready;
  first.state.queued_packets = [packet(auth.public)]; await first.save();
  let calls = 0;
  const recovered = new RuntimeTestingService({ root, privateRoot: join(root, "private"), authorization: auth.public, worker: async () => { calls++; } });
  await recovered.start(); assert.equal(recovered.server, null); await recovered.contact();
  const evidence = await verifyRuntimeEvidenceFiles(join(root, "evidence-set.json"));
  assert.equal(evidence.packets[0].execution_status, "SKIPPED"); assert.equal(evidence.packets[0].reason, "PROCESS_RECOVERY_QUEUE_INTERRUPTED");
  assert.equal(calls, 0); await recovered.shutdown();
});

test("预算耗尽记 SKIPPED，清理仍使用独立预留预算", async t => {
  const root = await temporary(t); const auth = grant();
  const controller = new RuntimeTestingController({ root, authorization: auth.public }); await controller.ready;
  controller.state.elapsed_ms = auth.public.budget_ms - auth.public.cleanup_reserve_ms;
  assert.equal(await controller.start(packet(auth.public)), null);
  assert.equal(controller.state.packets[0].reason, "BUDGET_EXHAUSTED");
  const cleanup = await controller.start(packet(auth.public, "CLEANUP", "cleanup-1")); assert.equal(cleanup.duration, auth.public.cleanup_reserve_ms);
  await controller.cancel();
});

function review(intake, evidence, role, refs = {}) {
  const verdicts = { AFFIRMATIVE: "PROVEN", NEGATIVE: "UPHELD", MODERATOR: "TRUE_POSITIVE" };
  const active = intake.findings.length + intake.runtime_candidates.length > 0;
  return seal({ schema_version: 3, artifact_type: "evidence-truth-review", audit_id: intake.audit_id, round: 1, role,
    execution_status: active ? "COMPLETE" : "NOT_APPLICABLE", agent_session_id: active ? `session-${role}` : null,
    intake_digest: intake.artifact_digest, runtime_evidence_digest: evidence.artifact_digest, ...refs,
    reviewed_finding_ids: intake.findings.map(row => row.finding_id),
    findings: intake.findings.map(row => ({ finding_id: row.finding_id, verdict: verdicts[role], claims: ["源码边界证据成立。"], evidence_refs: ["src/fixture.js:1"], reasoning: "已独立核查关键源码证据与反证。", gaps: [],
      runtime_review: { evidence_validity: "NOT_APPLICABLE", packet_ids: [], reasoning: "此项没有绑定运行测试。" } })),
    runtime_findings: intake.runtime_candidates.map(row => ({ finding_id: row.finding_id, claim_scope: "RUNTIME_ONLY", source_mapping: "UNKNOWN", packet_id: row.packet_id,
      verdict: verdicts[role], reasoning: "真实应用运行证据成立，源码映射仍未知。", gaps: ["未确认部署版本与源码一致。"], evidence_refs: [`runtime-testing/${row.packet_id}.result.json`] })) });
}

test("新协议完整复核源码与运行候选，拒绝混用旧 quick 和跳过角色", async t => {
  const root = await temporary(t); const auth = grant({ context: "" }); const controller = new RuntimeTestingController({ root, authorization: auth.public }); await controller.ready;
  const evidence = await controller.close();
  const intake = seal({ schema_version: 3, artifact_type: "finding-truth-validation-intake", audit_id: auth.public.audit_id, round: 1, scope_digest: SHA,
    policy: { runtime_testing: { protocol: PROTOCOL, evidence_digest: evidence.artifact_digest, authorization_digest: evidence.authorization_digest }, static_review: "AFFIRMATIVE_NEGATIVE_MODERATOR", full_dynamic_trigger: "MANUAL_ONLY" },
    findings: [{ finding_id: "finding-1", finding_object_digest: SHA, finding_path: "reports/finding.json", adjudication_state: "SUPPORTED_STATIC", runtime_request_path: null }], runtime_candidates: [] });
  assert.deepEqual(validateTruthValidationIntake(intake), []);
  const affirmative = review(intake, evidence, "AFFIRMATIVE"); const negative = review(intake, evidence, "NEGATIVE", { affirmative_review_digest: affirmative.artifact_digest });
  const moderator = review(intake, evidence, "MODERATOR", { affirmative_review_digest: affirmative.artifact_digest, negative_review_digest: negative.artifact_digest });
  const routing = seal({ schema_version: 3, artifact_type: "finding-validation-routing-manifest", audit_id: intake.audit_id, round: 1, scope_digest: SHA,
    intake_digest: intake.artifact_digest, runtime_evidence_digest: evidence.artifact_digest, role_review_digests: { affirmative: affirmative.artifact_digest, negative: negative.artifact_digest, moderator: moderator.artifact_digest }, full_dynamic_trigger: "MANUAL_ONLY",
    findings: [{ finding_id: "finding-1", route: "EVIDENCE_THREE_PARTY", runtime_status: "SKIPPED", moderator_verdict: "TRUE_POSITIVE", final_verdict: "TRUE_POSITIVE", report_disposition: "FINDING", evidence_refs: [], rationale: "独立三方复核后确认源码证据成立。" }],
    runtime_findings: [], summary: { total: 1, true_positive: 1, false_positive: 0, inconclusive: 0 }, complete: true });
  const bundle = { intake, quickResultSet: evidence, affirmative, negative, moderator, routing };
  assert.deepEqual(validateTruthValidationBundle(bundle), []);
  assert.ok(validateTruthValidationBundle({ ...bundle, affirmative: seal({ ...affirmative, schema_version: 1 }) }).length);
  assert.ok(validateTruthValidationBundle({ ...bundle, moderator: seal({ ...moderator, agent_session_id: affirmative.agent_session_id }) }).length);
  const bypass = structuredClone(routing); bypass.findings[0].route = "QUICK_DYNAMIC"; bypass.findings[0].moderator_verdict = null;
  assert.ok(validateTruthValidationBundle({ ...bundle, routing: seal(bypass) }).length);
  assert.ok(validateStaticRoleReview(seal({ ...affirmative, findings: [], reviewed_finding_ids: [] }), { intake, quickResultSet: evidence, role: "AFFIRMATIVE" }).length);
  const tampered = seal({ ...evidence, authorization_digest: "b".repeat(64) });
  assert.ok(validateTruthValidationBundle({ ...bundle, quickResultSet: tampered }).length);
});

test("仅运行候选也必须启动三个独立角色，缺失逐项复核被拒绝", () => {
  const candidate = { finding_id: "runtime-explore-1", claim_scope: "RUNTIME_ONLY", source_mapping: "UNKNOWN", packet_id: "explore-1", vulnerability_type_id: "JW-ACCESS-01", evidence_digest: SHA, scope_digest: SHA };
  const evidence = { artifact_digest: SHA, packets: [] };
  const intake = seal({ schema_version: 3, artifact_type: "finding-truth-validation-intake", audit_id: "audit-runtime-test", round: 1, scope_digest: SHA,
    policy: { runtime_testing: { protocol: PROTOCOL, evidence_digest: SHA, authorization_digest: SHA }, static_review: "AFFIRMATIVE_NEGATIVE_MODERATOR", full_dynamic_trigger: "MANUAL_ONLY" }, findings: [], runtime_candidates: [candidate] });
  const affirmative = review(intake, evidence, "AFFIRMATIVE");
  assert.deepEqual(validateStaticRoleReview(affirmative, { intake, quickResultSet: evidence, role: "AFFIRMATIVE" }), []);
  assert.ok(validateStaticRoleReview(seal({ ...affirmative, execution_status: "NOT_APPLICABLE", agent_session_id: null }), { intake, quickResultSet: evidence, role: "AFFIRMATIVE" }).length);
  assert.ok(validateStaticRoleReview(seal({ ...affirmative, runtime_findings: [] }), { intake, quickResultSet: evidence, role: "AFFIRMATIVE" }).length);
});

test("缺少环境的 v3 空候选审计可完成封存，旧模型不能冒充新协议交付", async t => {
  const root = await temporary(t); const reportsRoot = join(root, "reports"); const auth = grant({ context: "" });
  const runtimeRoot = join(reportsRoot, "runtime-testing", auth.public.audit_id);
  const controller = new RuntimeTestingController({ root: runtimeRoot, authorization: auth.public }); await controller.ready;
  const evidence = await controller.close();
  const intake = seal({ schema_version: 3, artifact_type: "finding-truth-validation-intake", audit_id: auth.public.audit_id, round: 1, scope_digest: SHA,
    policy: { runtime_testing: { protocol: PROTOCOL, evidence_digest: evidence.artifact_digest, authorization_digest: evidence.authorization_digest }, static_review: "AFFIRMATIVE_NEGATIVE_MODERATOR", full_dynamic_trigger: "MANUAL_ONLY" }, findings: [], runtime_candidates: [] });
  const affirmative = review(intake, evidence, "AFFIRMATIVE"); const negative = review(intake, evidence, "NEGATIVE", { affirmative_review_digest: affirmative.artifact_digest });
  const moderator = review(intake, evidence, "MODERATOR", { affirmative_review_digest: affirmative.artifact_digest, negative_review_digest: negative.artifact_digest });
  const routing = seal({ schema_version: 3, artifact_type: "finding-validation-routing-manifest", audit_id: intake.audit_id, round: 1, scope_digest: SHA,
    intake_digest: intake.artifact_digest, runtime_evidence_digest: evidence.artifact_digest, role_review_digests: { affirmative: affirmative.artifact_digest, negative: negative.artifact_digest, moderator: moderator.artifact_digest }, full_dynamic_trigger: "MANUAL_ONLY", findings: [], runtime_findings: [], summary: { total: 0, true_positive: 0, false_positive: 0, inconclusive: 0 }, complete: true });
  await mkdir(join(reportsRoot, "validation"), { recursive: true }); await mkdir(join(reportsRoot, "final"), { recursive: true });
  const inputs = {};
  for (const [key, value] of Object.entries({ truth_validation_intake: intake, affirmative_review: affirmative, negative_review: negative, moderator_review: moderator, validation_routing: routing })) {
    inputs[key] = join(reportsRoot, "validation", `${key}.json`); await writeFile(inputs[key], JSON.stringify(value));
  }
  for (const key of ["coverage_summary", "adjudication_input", "adjudication", "cvss_assessment", "attack_chains"]) inputs[key] = `reports/${key}.json`;
  inputs.runtime_testing_evidence = join(runtimeRoot, "evidence-set.json");
  const source = (artifact, digest) => ({ artifact, digest, json_pointer: "/summary" });
  const model = { schema_version: 3, audit_id: intake.audit_id, scope_digest: SHA, report_kind: "FINAL", inputs,
    coverage: { summary_digest: SHA, coverage_status: "COMPLETE", seal_state: "FINALIZED_COMPLETE", policy_satisfied: true, metrics: [] },
    truth_validation: { routing_digest: routing.artifact_digest, full_dynamic_trigger: "MANUAL_ONLY", summary: routing.summary, source: source(inputs.validation_routing, routing.artifact_digest) },
    runtime_testing: { protocol: PROTOCOL, evidence_digest: evidence.artifact_digest, authorization_digest: evidence.authorization_digest, status: evidence.status, reason: evidence.reason, cleanup_status: evidence.cleanup_status, packets: [], runtime_only_findings: [], source: source(inputs.runtime_testing_evidence, evidence.artifact_digest) },
    findings: [], excluded_findings: [], chains: [], rejected_chains: [] };
  model.manifest_digest = finalReportModelDigest(model);
  const path = join(reportsRoot, "final", `security-audit-report-model.${intake.audit_id}.json`); await writeFile(path, JSON.stringify(model));
  const audit = { id: intake.audit_id, source_baseline: { scope_digest: SHA }, paths: { workspace_root: root }, runtime_testing_state: controller.snapshot() };
  assert.equal(await verifyIntegratedFinalReport({ audit, reportsRoot }), true);
  model.detail_contract = "audit-report-details.v1"; model.delivery_gaps = [];
  model.runtime_testing.details = { evidence, reviews: [affirmative, negative, moderator].map(value => ({ role: value.role, session_id: value.agent_session_id,
    findings: value.runtime_findings, source: { ...source(inputs[`${value.role.toLowerCase()}_review`], value.artifact_digest), json_pointer: "/runtime_findings" } })) };
  model.manifest_digest = finalReportModelDigest(model); await writeFile(path, JSON.stringify(model));
  assert.equal(await verifyIntegratedFinalReport({ audit, reportsRoot }), true);
  model.runtime_testing.details.reviews[0].session_id = "unbound-session";
  model.manifest_digest = finalReportModelDigest(model); await writeFile(path, JSON.stringify(model));
  await assert.rejects(verifyIntegratedFinalReport({ audit, reportsRoot }), /only-review-details-mismatch/);
  model.runtime_testing.details.reviews[0].session_id = affirmative.agent_session_id;
  model.schema_version = 2; model.manifest_digest = finalReportModelDigest(model); await writeFile(path, JSON.stringify(model));
  await assert.rejects(verifyIntegratedFinalReport({ audit, reportsRoot }), /protocol-mismatch/);
});
