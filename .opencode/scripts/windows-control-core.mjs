import { createHash, randomUUID } from "node:crypto";
import { win32 } from "node:path";

export const WINAPP_VERSION = "0.6.0";
export const CONTROL_ACTIONS = Object.freeze(["inspect", "set_value", "invoke", "get_state", "wait_for"]);
const ID = /^[A-Za-z][A-Za-z0-9_.-]{0,79}$/;
const HASH = /^[a-f0-9]{64}$/;
const MAX_STEPS = 50;
const validId = value => typeof value === "string" && ID.test(value);

export function controlError(code) {
  return Object.assign(new Error("Windows 控制步骤未通过校验，已停止执行。"), { controlCode: code });
}

function requireThat(condition, code) {
  if (!condition) throw controlError(code);
}

function object(value, keys, code = "INVALID_SPEC") {
  requireThat(value && typeof value === "object" && !Array.isArray(value), code);
  requireThat(Object.keys(value).every(key => keys.includes(key)), code);
}

export function localExePath(value) {
  requireThat(typeof value === "string" && /^[A-Za-z]:[\\/]/.test(value), "LOCAL_EXE_REQUIRED");
  requireThat(!/[\x00-\x1f<>"|?*]/.test(value) && !value.slice(2).includes(":"), "LOCAL_EXE_REQUIRED");
  requireThat(value.slice(3).split(/[\\/]/).every(part => part && part !== "." && part !== ".." && !/[. ]$/.test(part)), "LOCAL_EXE_REQUIRED");
  requireThat(win32.extname(value).toLowerCase() === ".exe", "LOCAL_EXE_REQUIRED");
  return win32.normalize(value);
}

export function canonicalDigest(value) {
  const sort = item => Array.isArray(item) ? item.map(sort)
    : item && typeof item === "object" ? Object.fromEntries(Object.keys(item).sort().map(key => [key, sort(item[key])])) : item;
  return createHash("sha256").update(JSON.stringify(sort(value))).digest("hex");
}

// This is a standalone control-probe contract, not a P08 vulnerability result.
export function authorizeWindowsControl(spec, { enabled = false, platform = process.platform, now = Date.now() } = {}) {
  const skipped = reason => ({ status: "SKIPPED", reason });
  if (!enabled) return skipped("WINDOWS_CONTROL_DISABLED");
  if (spec?.authorization?.explicit_authorization !== true || spec?.authorization?.test_environment !== true) return skipped("AUTHORIZATION_REQUIRED");
  if (platform !== "win32") return skipped("WINDOWS_HOST_REQUIRED");
  try {
    object(spec, ["schema_version", "task_id", "authorization", "tool", "target", "controls", "cleanup"]);
    requireThat(spec.schema_version === 1 && validId(spec.task_id), "INVALID_SPEC");
    const auth = spec.authorization;
    object(auth, ["explicit_authorization", "test_environment", "synthetic_data_only", "network_mode", "account_mode", "expires_at"]);
    requireThat(auth.synthetic_data_only === true && auth.network_mode === "offline_fixture", "OFFLINE_FIXTURE_REQUIRED");
    requireThat(["anonymous", "preauthenticated_test_session"].includes(auth.account_mode), "TEST_LOGIN_REQUIRED");
    const expiration = Date.parse(auth.expires_at);
    requireThat(typeof auth.expires_at === "string" && expiration > now && expiration - now <= 24 * 60 * 60 * 1000, "AUTHORIZATION_EXPIRED");
    object(spec.tool, ["path", "sha256", "version"]);
    localExePath(spec.tool.path);
    requireThat(HASH.test(spec.tool.sha256) && spec.tool.version === WINAPP_VERSION, "WINAPP_VERSION_OR_HASH_INVALID");
    const target = spec.target;
    object(target, ["exe_path", "exe_sha256", "pid", "start_time_ticks", "hwnd", "windows_session_id"]);
    localExePath(target.exe_path);
    requireThat(HASH.test(target.exe_sha256), "TARGET_HASH_REQUIRED");
    requireThat(Number.isSafeInteger(target.pid) && target.pid > 0 && target.pid <= 0xffffffff, "TARGET_PID_INVALID");
    requireThat(typeof target.start_time_ticks === "string" && /^\d{15,19}$/.test(target.start_time_ticks), "TARGET_START_TIME_REQUIRED");
    requireThat(typeof target.hwnd === "string" && /^[1-9]\d{0,18}$/.test(target.hwnd) && BigInt(target.hwnd) <= 9223372036854775807n, "TARGET_HWND_INVALID");
    requireThat(Number.isSafeInteger(target.windows_session_id) && target.windows_session_id > 0, "INTERACTIVE_SESSION_REQUIRED");
    requireThat(Array.isArray(spec.controls) && spec.controls.length > 0 && spec.controls.length <= 16, "CONTROLS_REQUIRED");
    const ids = new Set();
    const selectors = new Set();
    for (const control of spec.controls) {
      object(control, ["id", "automation_id", "actions"]);
      requireThat(validId(control.id) && validId(control.automation_id), "CONTROL_ID_INVALID");
      requireThat(!ids.has(control.id) && !selectors.has(control.automation_id), "CONTROL_DUPLICATE");
      ids.add(control.id); selectors.add(control.automation_id);
      requireThat(Array.isArray(control.actions) && control.actions.length > 0 && new Set(control.actions).size === control.actions.length
        && control.actions.every(action => CONTROL_ACTIONS.includes(action)), "CONTROL_ACTION_INVALID");
    }
    object(spec.cleanup, ["invoke_control_id", "verify_control_id"]);
    requireThat(spec.controls.some(control => control.id === spec.cleanup.invoke_control_id && control.actions.includes("invoke"))
      && spec.controls.some(control => control.id === spec.cleanup.verify_control_id && control.actions.includes("get_state")), "CLEANUP_REQUIRED");
    const normalized = structuredClone(spec);
    normalized.tool.path = localExePath(spec.tool.path);
    normalized.target.exe_path = localExePath(spec.target.exe_path);
    return { status: "AUTHORIZED", binding_digest: canonicalDigest(normalized), spec: normalized };
  } catch (error) {
    return skipped(error.controlCode ?? "INVALID_SPEC");
  }
}

export function compileControlCommand(action, control, target, marker) {
  requireThat(CONTROL_ACTIONS.includes(action) && control.actions.includes(action), "ACTION_NOT_ALLOWED");
  requireThat(validId(control.automation_id), "CONTROL_ID_INVALID");
  const verbs = { inspect: "inspect", set_value: "set-value", invoke: "invoke", get_state: "get-value", wait_for: "wait-for" };
  const args = ["ui", verbs[action], control.automation_id];
  if (action === "set_value") args.push(marker);
  args.push("-w", target.hwnd, "--json");
  if (action === "inspect") args.push("--depth", "1");
  if (action === "wait_for") args.push("--value", marker, "--timeout", "3000");
  return args;
}

export function parseWinappJson(stdout) {
  requireThat(typeof stdout === "string" && Buffer.byteLength(stdout) <= 1024 * 1024, "CLI_OUTPUT_LIMIT");
  let value;
  try { value = JSON.parse(stdout.replace(/^\uFEFF/, "")); } catch { throw controlError("CLI_JSON_INVALID"); }
  requireThat(value && typeof value === "object", "CLI_JSON_INVALID");
  requireThat(!Object.hasOwn(value, "error") && value.success !== false, "CLI_REPORTED_ERROR");
  requireThat(!value.warnings || (Array.isArray(value.warnings) && value.warnings.length === 0), "CLI_WARNING");
  return value;
}

export function validateWinappSchema(schema) {
  requireThat(schema?.version === WINAPP_VERSION && schema.schemaVersion === "1.0", "CLI_SCHEMA_VERSION_INVALID");
  for (const verb of ["inspect", "set-value", "invoke", "get-value", "wait-for"]) {
    const command = schema.subcommands?.ui?.subcommands?.[verb];
    requireThat(command?.arguments?.selector && command.options?.["--window"] && command.options?.["--json"], "CLI_SCHEMA_INCOMPATIBLE");
  }
  requireThat(schema.subcommands.ui.subcommands["set-value"].arguments.value
    && schema.subcommands.ui.subcommands.inspect.options["--depth"]
    && schema.subcommands.ui.subcommands["wait-for"].options["--value"]
    && schema.subcommands.ui.subcommands["wait-for"].options["--timeout"], "CLI_SCHEMA_INCOMPATIBLE");
  return canonicalDigest(schema);
}

// Never publish raw values, titles, names, stdout, stderr or native error text.
export function summarizeControlResult(action, raw, control, target, marker) {
  const expected = control.automation_id;
  if (action === "inspect") {
    requireThat(Array.isArray(raw.windows) && raw.windows.length === 1, "INSPECT_SHAPE_INVALID");
    const window = raw.windows[0];
    requireThat(String(window.hwnd) === target.hwnd && Array.isArray(window.elements), "INSPECT_TARGET_MISMATCH");
    const found = [];
    let count = 0;
    const walk = elements => {
      for (const item of elements) {
        requireThat(++count <= 128 && item && typeof item === "object", "INSPECT_OUTPUT_LIMIT");
        if (item.selector === expected && item.automationId === expected) found.push(item);
        if (item.children) { requireThat(Array.isArray(item.children), "INSPECT_SHAPE_INVALID"); walk(item.children); }
      }
    };
    walk(window.elements);
    requireThat(found.length === 1, "SELECTOR_NOT_UNIQUE");
    return { control_id: control.id, observed: true, enabled: found[0].isEnabled === true };
  }
  if (action === "wait_for") {
    requireThat(raw.found === true && raw.element?.selector === expected && raw.element?.automationId === expected, "WAIT_RESULT_INVALID");
    return { control_id: control.id, marker_present: true };
  }
  requireThat(raw.elementId === expected, "CLI_RESULT_TARGET_MISMATCH");
  if (action === "get_state") {
    requireThat(typeof raw.text === "string" || raw.text === null, "VALUE_SHAPE_INVALID");
    return { control_id: control.id, marker_present: typeof raw.text === "string" && raw.text.includes(marker) };
  }
  if (action === "invoke") requireThat(String(raw.hwnd) === target.hwnd && raw.pattern === "InvokePattern", "INVOKE_RESULT_INVALID");
  if (action === "set_value") requireThat(String(raw.hwnd) === target.hwnd, "SET_VALUE_RESULT_INVALID");
  return { control_id: control.id, command_completed: true, effect_verified: false };
}

export class WindowsControlSession {
  #spec;
  #native;
  #release;
  #busy = false;
  #mutated = false;
  #steps = 0;
  #clock;
  #deadline;
  #events = [];
  #marker = `audit-winapp-${randomUUID()}`;
  #status = "NEW";
  #binding;
  #schemaDigest;
  #cleanupFailure = null;
  #closedResult = null;

  constructor(spec, native, { enabled = false, platform = process.platform, now = Date.now } = {}) {
    this.#clock = now;
    const auth = authorizeWindowsControl(spec, { enabled, platform, now: now() });
    this.#status = auth.status;
    this.reason = auth.reason ?? null;
    this.#spec = auth.spec;
    this.#binding = auth.binding_digest;
    this.#native = native;
    this.#deadline = now() + 5 * 60 * 1000;
  }

  status() {
    return { status: this.#status, reason: this.reason, binding_digest: this.#binding ?? null,
      verification_level: "CONTROL_PROBE_ONLY", vulnerability_confirmed: false,
      proof_marker: this.#spec ? this.#marker : null,
      schema_digest: this.#schemaDigest ?? null, cleanup_required: this.#mutated, steps: this.#steps };
  }

  events() { return structuredClone(this.#events); }

  validateAction(action, controlId) {
    const control = this.#spec?.controls.find(item => item.id === controlId);
    requireThat(control && CONTROL_ACTIONS.includes(action) && control.actions.includes(action), "ACTION_NOT_ALLOWED");
    requireThat(control.id !== this.#spec.cleanup.invoke_control_id, "USE_CLEANUP_TOOL");
  }

  #record(action, state, code = null) {
    this.#events.push({ sequence: this.#events.length + 1, action, status: state, code, recorded_at: new Date(this.#clock()).toISOString() });
  }

  async open() {
    if (this.#status === "SKIPPED") return this.status();
    requireThat(!this.#busy, "SESSION_BUSY");
    requireThat(this.#status === "AUTHORIZED", "SESSION_NOT_AUTHORIZED");
    this.#busy = true;
    this.#status = "PREPARING";
    try {
      requireThat(this.#clock() < Date.parse(this.#spec.authorization.expires_at), "AUTHORIZATION_EXPIRED");
      this.#release = await this.#native.acquire(this.#spec.target.windows_session_id, { task_id: this.#spec.task_id, binding_digest: this.#binding });
      await this.#native.checkFiles(this.#spec);
      const version = (await this.#native.execute(this.#spec.tool.path, ["--version"])).trim();
      requireThat(new RegExp(`^(?:winapp(?: CLI)?[ /])?v?${WINAPP_VERSION.replaceAll(".", "\\.")}(?:\\+[A-Za-z0-9.-]+)?$`, "i").test(version), "CLI_VERSION_MISMATCH");
      this.#schemaDigest = validateWinappSchema(parseWinappJson(await this.#native.execute(this.#spec.tool.path, ["--cli-schema"])));
      await this.#native.guard(this.#spec.target);
      this.#deadline = this.#clock() + 5 * 60 * 1000;
      this.#status = "READY";
      this.#record("open", "READY");
    } catch (error) {
      this.#status = "BLOCKED"; this.reason = error.controlCode ?? "NATIVE_CONTROL_FAILED";
      this.#record("open", "BLOCKED", this.reason);
      await this.#releaseLease();
    } finally { this.#busy = false; }
    return this.status();
  }

  async #perform(action, controlId, cleanup = false) {
    requireThat(this.#status === "READY" || (cleanup && this.#status === "CLEANING"), "SESSION_NOT_READY");
    requireThat(this.#clock() < Date.parse(this.#spec.authorization.expires_at), "AUTHORIZATION_EXPIRED");
    if (!cleanup) requireThat(this.#clock() < this.#deadline && this.#steps < MAX_STEPS, "SESSION_BUDGET_EXCEEDED");
    const control = this.#spec.controls.find(item => item.id === controlId);
    requireThat(control && control.actions.includes(action), "ACTION_NOT_ALLOWED");
    if (!cleanup) requireThat(control.id !== this.#spec.cleanup.invoke_control_id, "USE_CLEANUP_TOOL");
    const args = compileControlCommand(action, control, this.#spec.target, this.#marker);
    await this.#native.checkFiles(this.#spec);
    const before = await this.#native.guard(this.#spec.target, control.automation_id);
    requireThat(before?.is_password === false && before?.subtree_has_password === false && before?.enabled === true, "CONTROL_UNSAFE");
    requireThat(typeof before.runtime_id === "string" && before.runtime_id.length > 0, "CONTROL_IDENTITY_MISSING");
    if (["get_state", "wait_for"].includes(action)) requireThat(before.is_leaf === true, "LEAF_CONTROL_REQUIRED");
    if (action === "invoke") requireThat(before.can_invoke === true, "DIRECT_INVOKE_REQUIRED");
    if (action === "set_value") requireThat(before.can_set_value === true, "VALUE_PATTERN_REQUIRED");
    this.#steps += 1;
    if (["invoke", "set_value"].includes(action)) this.#mutated = true;
    const raw = parseWinappJson(await this.#native.execute(this.#spec.tool.path, args));
    const after = await this.#native.guard(this.#spec.target, control.automation_id);
    requireThat(after.runtime_id === before.runtime_id && after.is_password === false && after.subtree_has_password === false, "CONTROL_CHANGED");
    const result = summarizeControlResult(action, raw, control, this.#spec.target, this.#marker);
    this.#record(action, "COMPLETED");
    return result;
  }

  async act(action, controlId) {
    requireThat(!this.#busy, "SESSION_BUSY");
    this.#busy = true;
    try { return await this.#perform(action, controlId); }
    catch (error) {
      const code = error.controlCode ?? "NATIVE_CONTROL_FAILED";
      this.#status = "BLOCKED"; this.reason = code;
      this.#record(CONTROL_ACTIONS.includes(action) ? action : "invalid_action", "BLOCKED", code);
      throw controlError(code);
    } finally { this.#busy = false; }
  }

  async cleanup() {
    requireThat(!this.#busy, "SESSION_BUSY");
    if (this.#cleanupFailure) return structuredClone(this.#cleanupFailure);
    if (!this.#mutated) return { status: "NOT_REQUIRED" };
    requireThat(this.#release && !["CLOSED", "SKIPPED"].includes(this.#status), "SESSION_CLOSED");
    this.#busy = true;
    this.#status = "CLEANING";
    try {
      await this.#perform("invoke", this.#spec.cleanup.invoke_control_id, true);
      const state = await this.#perform("get_state", this.#spec.cleanup.verify_control_id, true);
      requireThat(state.marker_present === false, "CLEANUP_MARKER_PERSISTS");
      this.#mutated = false;
      this.#status = "READY"; this.reason = null;
      this.#record("cleanup", "SUCCEEDED");
      return { status: "SUCCEEDED", verified: true };
    } catch (error) {
      this.#status = "BLOCKED"; this.reason = error.controlCode ?? "CLEANUP_FAILED";
      this.#record("cleanup", "FAILED", this.reason);
      this.#cleanupFailure = { status: "FAILED", reason: this.reason, manual_remediation: "请在授权测试应用内清理本任务 marker，并核对残留测试数据。" };
      return structuredClone(this.#cleanupFailure);
    } finally { this.#busy = false; }
  }

  async #releaseLease() {
    if (this.#release) { const release = this.#release; this.#release = null; await release(); }
  }

  async close() {
    requireThat(!this.#busy, "SESSION_BUSY");
    if (this.#closedResult) return structuredClone(this.#closedResult);
    const cleanup = await this.cleanup();
    // Preserve a dirty lease on cleanup failure; no automatic unsafe recovery.
    if (cleanup.status !== "FAILED") await this.#releaseLease();
    if (this.#status !== "SKIPPED") this.#status = cleanup.status === "FAILED" ? "BLOCKED" : "CLOSED";
    this.#closedResult = { ...this.status(), cleanup, events: this.events() };
    return structuredClone(this.#closedResult);
  }
}
