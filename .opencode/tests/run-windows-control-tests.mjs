#!/usr/bin/env node
import { strict as assert } from "node:assert";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { WindowsControlSession, authorizeWindowsControl, canonicalDigest, compileControlCommand,
  controlError, parseWinappJson, summarizeControlResult, validateWinappSchema } from "../scripts/windows-control-core.mjs";
import { acquireDesktopLease, executeFile } from "../scripts/windows-control-native.mjs";
import { runControlProbe, validateControlPlan } from "../scripts/windows-control-cli.mjs";
import { createControlMcp } from "../scripts/windows-control-mcp.mjs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const portableMacOS = process.platform === "darwin" && process.env.AUDIT_ALLOW_MACOS_PORTABLE_TESTS === "1";
if (!["win32", "linux"].includes(process.platform) && !portableMacOS) {
  process.stdout.write('{"status":"SKIPPED","reason":"SUPPORTED_TEST_HOST_REQUIRED"}\n');
  process.exit(0);
}

function spec() {
  return { schema_version: 1, task_id: "fixture-task", authorization: { explicit_authorization: true, test_environment: true,
    synthetic_data_only: true, network_mode: "offline_fixture", account_mode: "anonymous", expires_at: new Date(Date.now() + 600_000).toISOString() },
  tool: { path: "C:\\Tools\\winapp.exe", sha256: "a".repeat(64), version: "0.6.0" },
  target: { exe_path: "C:\\Fixtures\\TestApp.exe", exe_sha256: "b".repeat(64), pid: 1234,
    start_time_ticks: "639238000000000000", hwnd: "123456", windows_session_id: 1 },
  controls: [
    { id: "input", automation_id: "MarkerInput", actions: ["inspect", "set_value", "get_state", "wait_for"] },
    { id: "submit", automation_id: "SubmitMarker", actions: ["invoke"] },
    { id: "clear", automation_id: "ClearMarker", actions: ["invoke"] },
  ], cleanup: { invoke_control_id: "clear", verify_control_id: "input" } };
}

function cliSchema() {
  const schema = { version: "0.6.0", schemaVersion: "1.0", subcommands: { ui: { subcommands: {} } } };
  for (const verb of ["inspect", "set-value", "invoke", "get-value", "wait-for"]) {
    schema.subcommands.ui.subcommands[verb] = { arguments: { selector: {} }, options: { "--window": {}, "--json": {} } };
  }
  schema.subcommands.ui.subcommands["set-value"].arguments.value = {};
  schema.subcommands.ui.subcommands.inspect.options["--depth"] = {};
  schema.subcommands.ui.subcommands["wait-for"].options["--value"] = {};
  schema.subcommands.ui.subcommands["wait-for"].options["--timeout"] = {};
  return schema;
}

function fakeNative() {
  const calls = [];
  const state = { value: "", releases: 0, guardFailure: false, password: false, failCleanup: false, uiFailure: false };
  const native = {
    async acquire(id) { calls.push(["acquire", id]); return async () => { state.releases += 1; }; },
    async checkFiles() { calls.push(["files"]); },
    async guard(_target, selector) {
      calls.push(["guard", selector]);
      if (state.guardFailure) throw controlError("TARGET_GUARD_FAILED");
      return { runtime_id: "1.2.3", is_password: state.password, subtree_has_password: state.password,
        enabled: true, is_leaf: true, can_invoke: true, can_set_value: true };
    },
    async execute(path, args) {
      calls.push(["execute", path, args]);
      if (args[0] === "--version") return "0.6.0\n";
      if (args[0] === "--cli-schema") return JSON.stringify(cliSchema());
      if (state.uiFailure) throw controlError("CLI_TIMEOUT");
      const selector = args[2];
      if (args[1] === "set-value") { state.value = args[3]; return JSON.stringify({ elementId: selector, hwnd: 123456 }); }
      if (args[1] === "invoke") {
        if (selector === "ClearMarker" && !state.failCleanup) state.value = "";
        return JSON.stringify({ elementId: selector, hwnd: 123456, pattern: "InvokePattern" });
      }
      if (args[1] === "get-value") return JSON.stringify({ elementId: selector, text: state.value });
      if (args[1] === "wait-for") return JSON.stringify({ found: true, waitedMs: 10, element: { selector, automationId: selector } });
      if (args[1] === "inspect") return JSON.stringify({ windows: [{ hwnd: 123456, title: "SECRET_WINDOW_TITLE", elements: [
        { selector, automationId: selector, name: "SECRET_CONTROL_NAME", value: "SECRET_VALUE", isEnabled: true },
      ] }] });
      throw new Error("unexpected fake command");
    },
  };
  return { native, calls, state };
}

const auth = value => authorizeWindowsControl(value, { enabled: true, platform: "win32" });
assert.equal(auth(spec()).status, "AUTHORIZED");
assert.equal(authorizeWindowsControl(spec()).reason, "WINDOWS_CONTROL_DISABLED");
assert.equal(authorizeWindowsControl(spec(), { enabled: true, platform: "linux" }).reason, "WINDOWS_HOST_REQUIRED");
for (const mutate of [
  value => { delete value.task_id; },
  value => { value.authorization.explicit_authorization = false; },
  value => { value.authorization.expires_at = "2000-01-01T00:00:00Z"; },
  value => { value.authorization.account_mode = "password"; },
  value => { value.authorization.password = "DO_NOT_LOG"; },
  value => { value.authorization.network_mode = "remote"; },
  value => { value.tool.version = "0.6.3"; },
  value => { value.target.exe_path = "\\\\remote\\share\\app.exe"; },
  value => { value.target.exe_path = "C:\\fixture\\..\\user\\app.exe"; },
  value => { value.target.exe_path = "C:\\fixture\\app.exe:stream.exe"; },
  value => { value.target.windows_session_id = 0; },
  value => { value.target.start_time_ticks = ""; },
  value => { value.controls[0].automation_id = "--allow-system-keys"; },
  value => { value.controls[0].actions.push("send_keys"); },
  value => { value.controls.push(structuredClone(value.controls[0])); },
  value => { delete value.cleanup; },
]) {
  const value = spec(); mutate(value); assert.equal(auth(value).status, "SKIPPED");
  const fake = fakeNative();
  const session = new WindowsControlSession(value, fake.native, { enabled: true, platform: "win32" });
  await session.open(); await session.close(); assert.equal(fake.calls.length, 0);
}
assert.equal(canonicalDigest({ a: 1, b: 2 }), canonicalDigest({ b: 2, a: 1 }));
assert.throws(() => parseWinappJson('{"error":"SECRET_NATIVE_ERROR"}'), { controlCode: "CLI_REPORTED_ERROR" });
assert.throws(() => parseWinappJson('{"warnings":["outside window"]}'), { controlCode: "CLI_WARNING" });
assert.throws(() => parseWinappJson('not json'), { controlCode: "CLI_JSON_INVALID" });
const incompatible = cliSchema(); delete incompatible.subcommands.ui.subcommands["wait-for"].options["--timeout"];
assert.throws(() => validateWinappSchema(incompatible), { controlCode: "CLI_SCHEMA_INCOMPATIBLE" });
const input = spec().controls[0];
assert.deepEqual(compileControlCommand("set_value", input, spec().target, "audit-marker"),
  ["ui", "set-value", "MarkerInput", "audit-marker", "-w", "123456", "--json"]);
assert.throws(() => summarizeControlResult("invoke", { elementId: "Ancestor", hwnd: 123456, pattern: "InvokePattern" }, spec().controls[1], spec().target, "marker"), { controlCode: "CLI_RESULT_TARGET_MISMATCH" });
assert.throws(() => summarizeControlResult("get_state", { elementId: "MarkerInput" }, input, spec().target, "marker"), { controlCode: "VALUE_SHAPE_INVALID" });
assert.throws(() => validateControlPlan({ steps: [{ action: "invoke", control_id: "clear" }] }, spec()), { controlCode: "PLAN_ACTION_NOT_ALLOWED" });

const fake = fakeNative();
const probe = await runControlProbe({ spec: spec(), enabled: true, platform: "win32", native: fake.native,
  plan: { steps: ["inspect", "set_value", "get_state", "wait_for"].map(action => ({ action, control_id: "input" })) } });
assert.equal(probe.control_probe_status, "COMPLETED");
assert.equal(probe.cleanup.status, "SUCCEEDED");
assert.equal(probe.verification_level, "CONTROL_PROBE_ONLY");
assert.equal(probe.vulnerability_confirmed, false);
assert.equal(fake.state.releases, 1);
assert.equal(probe.results[2].marker_present, true);
assert.equal(JSON.stringify(probe).includes("SECRET"), false);
assert.match(probe.proof_marker, /^audit-winapp-[a-f0-9-]+$/);
assert.equal(fake.calls.filter(call => call[0] === "execute" && call[2][1] === "invoke").length, 1);

const dirty = fakeNative(); dirty.state.failCleanup = true;
const dirtySession = new WindowsControlSession(spec(), dirty.native, { enabled: true, platform: "win32" });
await dirtySession.open(); await dirtySession.act("set_value", "input");
const dirtyResult = await dirtySession.close();
assert.equal(dirtyResult.cleanup.status, "FAILED");
assert.equal(dirtyResult.cleanup_required, true);
assert.equal(dirty.state.releases, 0);
const beforeClose = dirty.calls.length; await dirtySession.close(); assert.equal(dirty.calls.length, beforeClose);

const expiredFake = fakeNative();
let clock = Date.now();
const expiredSpec = spec();
const expiredSession = new WindowsControlSession(expiredSpec, expiredFake.native, { enabled: true, platform: "win32", now: () => clock });
clock = Date.parse(expiredSpec.authorization.expires_at) + 1;
assert.equal((await expiredSession.open()).reason, "AUTHORIZATION_EXPIRED");
assert.equal(expiredFake.calls.length, 0);

const concurrentFake = fakeNative();
const concurrentSession = new WindowsControlSession(spec(), concurrentFake.native, { enabled: true, platform: "win32" });
await concurrentSession.open();
const firstAction = concurrentSession.act("inspect", "input");
await assert.rejects(concurrentSession.act("invoke", "submit"), { controlCode: "SESSION_BUSY" });
await firstAction; await concurrentSession.close();

const changedFake = fakeNative();
const changedSession = new WindowsControlSession(spec(), changedFake.native, { enabled: true, platform: "win32" });
await changedSession.open();
const originalGuard = changedFake.native.guard;
let guardCount = 0;
changedFake.native.guard = async (...args) => ({ ...await originalGuard(...args), runtime_id: String(++guardCount) });
await assert.rejects(changedSession.act("inspect", "input"), { controlCode: "CONTROL_CHANGED" });
await changedSession.close();

for (const failure of ["guardFailure", "password", "uiFailure"]) {
  const native = fakeNative(); const session = new WindowsControlSession(spec(), native.native, { enabled: true, platform: "win32" });
  await session.open(); native.state[failure] = true;
  const before = native.calls.filter(call => call[0] === "execute").length;
  await assert.rejects(session.act("set_value", "input"));
  if (failure !== "uiFailure") assert.equal(native.calls.filter(call => call[0] === "execute").length, before);
  assert.equal(session.status().status, "BLOCKED");
  await session.close();
}

// Native transport options are checked with a fake exec callback; no process is spawned.
let transportOptions;
assert.equal(await executeFile("C:\\Tools\\winapp.exe", ["ui", "inspect"], { exec: (_command, _args, options, callback) => {
  transportOptions = options; callback(null, "{}", "");
} }), "{}");
assert.equal(transportOptions.shell, false);
assert.ok(transportOptions.timeout <= 8000 && transportOptions.maxBuffer <= 1024 * 1024);
await assert.rejects(executeFile("x", [], { exec: (_c, _a, _o, callback) => callback(new Error("SECRET"), "SECRET", "SECRET") }), error => !error.message.includes("SECRET"));

const directory = await mkdtemp(join(tmpdir(), "winapp-lease-contract-"));
try {
  const release = await acquireDesktopLease(1, { directory });
  await assert.rejects(acquireDesktopLease(1, { directory }), { controlCode: "DESKTOP_BUSY_OR_DIRTY" });
  await release(); const secondRelease = await acquireDesktopLease(1, { directory }); await secondRelease();
} finally { await rm(directory, { recursive: true, force: true }); }

// Exercise real MCP request dispatch on an in-memory transport, with a fake native backend.
const mcpFake = fakeNative();
const mcpSession = new WindowsControlSession(spec(), mcpFake.native, { enabled: true, platform: "win32" });
const { server, shutdown } = createControlMcp(mcpSession);
const client = new Client({ name: "winapp-contract", version: "1" });
const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
await server.connect(serverTransport); await client.connect(clientTransport);
assert.ok((await client.listTools()).tools.some(tool => tool.name === "inspect"));
await client.callTool({ name: "status", arguments: {} }); assert.equal(mcpFake.calls.length, 0);
const invalid = await client.callTool({ name: "invoke", arguments: { control_id: "submit", hwnd: "9999" } });
assert.equal(invalid.isError, true); assert.equal(mcpFake.calls.length, 0);
const foreignControl = await client.callTool({ name: "invoke", arguments: { control_id: "foreign-window" } });
assert.equal(foreignControl.isError, true); assert.equal(mcpFake.calls.length, 0);
const write = await client.callTool({ name: "set_value", arguments: { control_id: "input" } });
assert.equal(write.isError, false);
const closed = await client.callTool({ name: "close", arguments: {} });
assert.equal(JSON.parse(closed.content[0].text).cleanup.status, "SUCCEEDED");
await shutdown(); await client.close(); await server.close();
assert.equal(mcpFake.state.releases, 1);

process.stdout.write('{"status":"PASS","suite":"windows-control","mode":"MOCK_ONLY","native_targets_contacted":false}\n');
