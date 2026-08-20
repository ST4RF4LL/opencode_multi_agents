import { createHash, randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { appendFile, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, stat, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { validateExternalRuntimeValidationRequest } from "../../skills/common-subagent/finding-evidence-contract/scripts/external-runtime-validation-contract.mjs";
import { validateStageEnvelope } from "../../skills/common-subagent/audit-artifact-management/scripts/stage-agent-contract.mjs";
import { buildOpenCodeEnvironment } from "./opencode-runtime-config.mjs";
import { normalizeOpenCodeModel } from "./opencode-model-settings.mjs";

const RUN_ID = /^[a-z0-9][a-z0-9._:-]{2,260}$/i;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const MAX_LOG_LINE = 16 * 1024;
const execFileAsync = promisify(execFile);

function safeRelative(root, candidate) {
  const absoluteRoot = resolve(root);
  const absolute = resolve(candidate);
  const value = relative(absoluteRoot, absolute);
  if (value.startsWith("..") || isAbsolute(value) || value.split(sep).includes("..")) return null;
  return value;
}

async function readJson(path, root) {
  if (safeRelative(root, path) === null) throw new Error("validation-artifact-outside-runtime-root");
  const linkInfo = await lstat(path);
  if (linkInfo.isSymbolicLink()) throw new Error("validation-artifact-symlink-forbidden");
  const [realRoot, realPath] = await Promise.all([realpath(root), realpath(path)]);
  if (safeRelative(realRoot, realPath) === null) throw new Error("validation-artifact-realpath-outside-runtime-root");
  const info = await stat(path);
  if (!info.isFile() || info.size > MAX_JSON_BYTES) throw new Error("validation-artifact-size-invalid");
  return JSON.parse(await readFile(path, "utf8"));
}

function validateLoopbackUrl(value) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && LOOPBACK.has(url.hostname) ? url : null;
  } catch {
    return null;
  }
}

function genericRedact(value) {
  return String(value)
    .replace(/(["']?(?:password|passwd|secret|token|authorization|cookie)["']?\s*[:=]\s*["']?)[^\s,"']+/gi, "$1[REDACTED]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[JWT_REDACTED]");
}

function redact(value, secrets = []) {
  let result = genericRedact(value);
  for (const secret of secrets.filter(Boolean).sort((a, b) => b.length - a.length)) result = result.replaceAll(secret, "[REDACTED]");
  return result.slice(0, MAX_LOG_LINE);
}

async function copyOptional(source, target) {
  try {
    await copyFile(source, target);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

async function createEphemeralOpenCodeHome(authSourceRoot = null) {
  const root = await mkdtemp(join(tmpdir(), "opencode-dynval-"));
  const dataHome = join(root, "data");
  const stateHome = join(root, "state");
  const tempHome = join(root, "tmp");
  const dataDirectory = join(dataHome, "opencode");
  await Promise.all([mkdir(dataDirectory, { recursive: true }), mkdir(stateHome, { recursive: true }), mkdir(tempHome, { recursive: true })]);
  const sourceData = authSourceRoot ?? join(process.env.XDG_DATA_HOME ?? join(homedir(), ".local", "share"), "opencode");
  await Promise.all([
    copyOptional(join(sourceData, "auth.json"), join(dataDirectory, "auth.json")),
    copyOptional(join(sourceData, "account.json"), join(dataDirectory, "account.json")),
  ]);
  return { root, dataHome, stateHome, tempHome };
}

function validateAuthorization(input) {
  const target = validateLoopbackUrl(input.target_base_url);
  if (input.explicit_authorization !== true || input.test_environment !== true) throw Object.assign(new Error("必须明确确认这是授权的测试环境。"), { statusCode: 422, code: "authorization-required" });
  if (!target) throw Object.assign(new Error("动态验证目标必须是 localhost、127.0.0.1 或 [::1] 的 HTTP(S) URL。"), { statusCode: 422, code: "target-not-loopback" });
  const attacker = input.attacker_account ?? {};
  const victim = input.victim_account ?? {};
  for (const [name, account] of [["attacker", attacker], ["victim", victim]]) {
    if (typeof account.username !== "string" || !account.username || account.username.length > 300
      || typeof account.password !== "string" || !account.password || account.password.length > 4096) {
      throw Object.assign(new Error(`${name} 测试账号不完整。`), { statusCode: 422, code: "test-account-required" });
    }
  }
  if (attacker.username === victim.username) throw Object.assign(new Error("攻击者与受害者必须使用两个不同测试账号。"), { statusCode: 422, code: "distinct-accounts-required" });
  for (const field of ["login_instructions", "cleanup_instructions"]) {
    if (typeof input[field] !== "string" || !input[field].trim() || input[field].length > 4000) {
      throw Object.assign(new Error(`${field} 缺失或过长。`), { statusCode: 422, code: "instructions-required" });
    }
  }
  return { target, attacker, victim };
}

function validationPrompt({ requestPath, envelopePath, target, attacker, victim, input, repository, executionPaths }) {
  return [
    "@dynamic-vulnerability-validator 执行一次用户明确授权的 localhost Web XSS 动态验证。",
    `密封 runtime-validation request：${requestPath}`,
    `密封 P08 input envelope：${envelopePath}`,
    `被测源码根目录 ${repository.path} 只读；不得在其中创建 reports、tmp、浏览器数据或任何其他文件。`,
    `当前执行工作区是 ${executionPaths.workspace_root}；所有相对 reports/** 输出必须通过该工作区落到工作台受控制品目录。`,
    `授权测试目标：${target.href}`,
    "用户已确认该环境和以下两个账号均为专用测试资产，不是生产、第三方或真实用户账号。",
    `attacker username: ${attacker.username}`,
    `attacker password: ${attacker.password}`,
    `victim username: ${victim.username}`,
    `victim password: ${victim.password}`,
    `login instructions: ${input.login_instructions.trim()}`,
    `cleanup instructions: ${input.cleanup_instructions.trim()}`,
    "严格遵守动态验证安全边界，使用 Chrome DevTools MCP 隔离上下文；保存脱敏证据并尝试清理。",
  ].join("\n");
}

function publicRun(run) {
  const { idempotency_digest, ephemeral_session_root, ...value } = run;
  return { ...value };
}

function safeEphemeralSessionRoot(path) {
  if (typeof path !== "string") return null;
  const resolved = resolve(path);
  return resolve(dirname(resolved)) === resolve(tmpdir()) && basename(resolved).startsWith("opencode-dynval-") ? resolved : null;
}

export class DynamicValidationRunner extends EventEmitter {
  constructor({ stateRoot, enabled = false, command = "opencode", spawnProcess = spawn, registryPath, rolesPath, authSourceRoot = null, resultValidator = null } = {}) {
    super();
    this.stateRoot = resolve(stateRoot);
    this.enabled = enabled;
    this.command = command;
    this.spawnProcess = spawnProcess;
    this.registryPath = resolve(registryPath);
    this.rolesPath = resolve(rolesPath);
    this.authSourceRoot = authSourceRoot ? resolve(authSourceRoot) : null;
    this.resultValidator = resultValidator;
    this.runs = new Map();
    this.processes = new Map();
    this.subscribers = new Map();
    this.queues = new Map();
    this.ready = this.initialize();
  }

  async initialize() {
    await mkdir(this.stateRoot, { recursive: true });
    const entries = await readdir(this.stateRoot, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      try {
        const run = JSON.parse(await readFile(join(this.stateRoot, entry.name, "run.json"), "utf8"));
        const ephemeralRoot = safeEphemeralSessionRoot(run.ephemeral_session_root);
        if (run.ephemeral_cleanup !== "SUCCEEDED" && ephemeralRoot) {
          await rm(ephemeralRoot, { recursive: true, force: true });
          run.ephemeral_cleanup = "SUCCEEDED";
          run.ephemeral_session_root = null;
        }
        if (["preparing", "running", "cancelling"].includes(run.status)) {
          run.status = "failed";
          run.error = "平台重启后无法恢复动态验证子进程；没有执行全局浏览器进程清理。";
          run.finished_at = new Date().toISOString();
        }
        run.updated_at = new Date().toISOString();
        this.runs.set(run.id, run);
        await this.persist(run);
      } catch {
        // Preserve invalid state directories for operator inspection.
      }
    }
  }

  enqueue(id, operation) {
    const prior = this.queues.get(id) ?? Promise.resolve();
    const next = prior.catch(() => {}).then(operation);
    this.queues.set(id, next);
    next.finally(() => { if (this.queues.get(id) === next) this.queues.delete(id); }).catch(() => {});
    return next;
  }

  directory(id) {
    return join(this.stateRoot, createHash("sha256").update(id).digest("hex").slice(0, 32));
  }

  async persist(run) {
    const directory = this.directory(run.id);
    await mkdir(directory, { recursive: true });
    const temporary = join(directory, `run.${process.pid}.${randomUUID()}.tmp`);
    await writeFile(temporary, `${JSON.stringify(run, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, join(directory, "run.json"));
  }

  async record(run, type, data = {}) {
    return this.enqueue(run.id, async () => {
      run.updated_at = new Date().toISOString();
      run.version += 1;
      run.event_sequence += 1;
      const event = { event_id: `evt_${randomUUID()}`, validation_id: run.id, sequence: run.event_sequence, occurred_at: run.updated_at, type, data };
      await this.persist(run);
      await appendFile(join(this.directory(run.id), "events.jsonl"), `${JSON.stringify(event)}\n`, { encoding: "utf8", mode: 0o600 });
      for (const subscriber of this.subscribers.get(run.id) ?? []) subscriber(event);
      return event;
    });
  }

  listRuns() {
    return [...this.runs.values()].map(publicRun).sort((a, b) => b.created_at.localeCompare(a.created_at));
  }

  getRun(id) {
    const run = this.runs.get(id);
    return run ? publicRun(run) : null;
  }

  async deleteAuditRuns(auditId) {
    await this.ready;
    const values = [...this.runs.values()].filter(run => run.audit_id === auditId);
    if (values.some(run => ["preparing", "running", "cancelling"].includes(run.status) || this.processes.has(run.id))) {
      throw Object.assign(new Error("该审计仍有动态验证正在运行；请先取消并等待验证结束。"), { statusCode: 409, code: "audit-validation-active" });
    }
    for (const run of values) {
      const queuedWrite = this.queues.get(run.id);
      if (queuedWrite) await queuedWrite;
      await rm(this.directory(run.id), { recursive: true, force: true });
      this.runs.delete(run.id);
      this.subscribers.delete(run.id);
      this.queues.delete(run.id);
    }
    return values.length;
  }

  async eventsSince(id, sequence = 0) {
    try {
      const content = await readFile(join(this.directory(id), "events.jsonl"), "utf8");
      return content.split("\n").filter(Boolean).map(line => JSON.parse(line)).filter(event => event.sequence > sequence);
    } catch (error) {
      if (error?.code === "ENOENT") return [];
      throw error;
    }
  }

  subscribe(id, listener) {
    const listeners = this.subscribers.get(id) ?? new Set();
    listeners.add(listener);
    this.subscribers.set(id, listeners);
    return () => listeners.delete(listener);
  }

  async validateArtifacts({ repository, reportsRoot, runtimeRoot, requestDescriptor, target }) {
    if (resolve(runtimeRoot) !== resolve(reportsRoot, "validation-handoff", "runtime")) {
      throw Object.assign(new Error("动态验证 runtime root 必须位于工作台为该仓库分配的 reports 路径。"), { statusCode: 422, code: "validation-runtime-root-invalid" });
    }
    const requestPath = join(runtimeRoot, requestDescriptor.request_path);
    const envelopePath = join(runtimeRoot, requestDescriptor.envelope_path);
    const [request, envelope, registry, roles] = await Promise.all([
      readJson(requestPath, runtimeRoot), readJson(envelopePath, runtimeRoot),
      JSON.parse(await readFile(this.registryPath, "utf8")), JSON.parse(await readFile(this.rolesPath, "utf8")),
    ]);
    const requestErrors = validateExternalRuntimeValidationRequest(request);
    const envelopeErrors = validateStageEnvelope(envelope, registry, { roles });
    if (requestErrors.length || envelopeErrors.length) throw Object.assign(new Error(`密封验证请求无效：${[...requestErrors, ...envelopeErrors].join(", ")}`), { statusCode: 422, code: "validation-request-invalid" });
    if (request.audit_id !== requestDescriptor.audit_id || request.finding_id !== requestDescriptor.finding_id
      || envelope.audit_id !== request.audit_id || envelope.agent_name !== "dynamic-vulnerability-validator") {
      throw Object.assign(new Error("验证请求与 P08 envelope 绑定不一致。"), { statusCode: 422, code: "validation-binding-mismatch" });
    }
    if (request.claim?.vulnerability_type_id !== "JW-INJECT-06") throw Object.assign(new Error("当前只支持 JW-INJECT-06 Web XSS。"), { statusCode: 422, code: "validation-type-unsupported" });
    const envelopeTarget = validateLoopbackUrl(envelope.payload?.localhost_target);
    if (!envelopeTarget || envelopeTarget.origin !== target.origin) {
      throw Object.assign(new Error("表单目标与密封 P08 envelope 的 localhost origin 不一致。"), { statusCode: 409, code: "validation-target-binding-mismatch" });
    }
    const currentCommit = (await execFileAsync("git", ["-C", repository.path, "rev-parse", "HEAD"], { encoding: "utf8", timeout: 10_000, maxBuffer: 1024 * 1024 })).stdout.trim();
    if (request.source_binding?.commit && request.source_binding.commit !== currentCommit) {
      throw Object.assign(new Error("当前仓库提交与密封验证请求不一致。"), { statusCode: 409, code: "validation-source-drift" });
    }
    return { request, envelope, requestPath, envelopePath };
  }

  async create({ input, repository, reportsRoot, runtimeRoot, executionPaths, requestDescriptor, idempotencyKey }) {
    await this.ready;
    if (!this.enabled) throw Object.assign(new Error("动态验证 Runner 未启用。"), { statusCode: 503, code: "dynamic-runner-disabled" });
    if (!idempotencyKey || idempotencyKey.length > 200) throw Object.assign(new Error("缺少有效的 Idempotency-Key。"), { statusCode: 400, code: "idempotency-key-required" });
    if (!RUN_ID.test(requestDescriptor.id)) throw Object.assign(new Error("验证 ID 非法。"), { statusCode: 422, code: "validation-id-invalid" });
    const existing = this.runs.get(requestDescriptor.id);
    const digest = createHash("sha256").update(idempotencyKey).digest("hex");
    if (existing?.idempotency_digest === digest) return publicRun(existing);
    if (existing && ["preparing", "running", "cancelling"].includes(existing.status)) throw Object.assign(new Error("该 finding 已有动态验证正在运行。"), { statusCode: 409, code: "validation-active" });
    if (requestDescriptor.result_present) throw Object.assign(new Error("该 finding 已存在动态验证结果；默认拒绝覆盖。"), { statusCode: 409, code: "validation-result-exists" });
    const authorization = validateAuthorization(input);
    const artifacts = await this.validateArtifacts({ repository, reportsRoot, runtimeRoot, requestDescriptor, target: authorization.target });
    const now = new Date().toISOString();
    const run = {
      id: requestDescriptor.id,
      audit_id: requestDescriptor.audit_id,
      finding_id: requestDescriptor.finding_id,
      repository_id: repository.id,
      request_digest: artifacts.request.packet_digest,
      target_origin: authorization.target.origin,
      account_roles: { attacker: "authorized-test-attacker", victim: "authorized-test-victim", distinct: true },
      status: "preparing",
      version: 1,
      event_sequence: 0,
      created_at: now,
      updated_at: now,
      finished_at: null,
      exit_code: null,
      error: null,
      ephemeral_cleanup: "PENDING",
      ephemeral_session_root: null,
      result_validation: "PENDING",
      idempotency_digest: digest,
    };
    this.runs.set(run.id, run);
    await this.persist(run);
    await this.record(run, "validation.preparing", { target_origin: run.target_origin });
    this.start({ run, repository, runtimeRoot, executionPaths, requestDescriptor, artifacts, authorization, input }).catch(async error => {
      run.status = "failed";
      run.error = genericRedact(error.message);
      run.finished_at = new Date().toISOString();
      await this.record(run, "validation.failed", { message: run.error });
    });
    return publicRun(run);
  }

  async start({ run, repository, runtimeRoot, executionPaths, requestDescriptor, artifacts, authorization, input }) {
    const ephemeral = await createEphemeralOpenCodeHome(this.authSourceRoot);
    run.ephemeral_session_root = ephemeral.root;
    await this.persist(run);
    const secrets = [authorization.attacker.username, authorization.attacker.password, authorization.victim.username, authorization.victim.password];
    const prompt = validationPrompt({ ...artifacts, target: authorization.target, attacker: authorization.attacker, victim: authorization.victim, input, repository, executionPaths });
    const authorizationFile = join(ephemeral.root, "dynamic-validation-authorization.txt");
    await writeFile(authorizationFile, prompt, { encoding: "utf8", mode: 0o600 });
    let child;
    try {
      const model = normalizeOpenCodeModel(requestDescriptor.model);
      child = this.spawnProcess(this.command, ["run", "--format", "json", ...(model ? ["--model", model] : []), "--agent", "dynamic-vulnerability-validator", "--dir", executionPaths.workspace_root, "--title", `动态验证 ${run.audit_id}/${run.finding_id}`, "--file", authorizationFile, "请读取所附授权说明并严格按 dynamic-vulnerability-validator 契约执行。"], {
        cwd: executionPaths.workspace_root,
        env: {
          ...await buildOpenCodeEnvironment(repository.config_path),
          AUDIT_SOURCE_ROOT: executionPaths.source_root,
          AUDIT_ENGINE_ROOT: resolve(dirname(repository.config_path), ".."),
          AUDIT_WORKSPACE_ROOT: executionPaths.workspace_root,
          AUDIT_REPORTS_ROOT: executionPaths.reports_root,
          AUDIT_TMP_ROOT: executionPaths.tmp_root,
          XDG_DATA_HOME: ephemeral.dataHome,
          XDG_STATE_HOME: ephemeral.stateHome,
          TMPDIR: ephemeral.tempHome,
        },
        stdio: ["ignore", "pipe", "pipe"],
        shell: false,
      });
    } catch (error) {
      secrets.fill("");
      await rm(ephemeral.root, { recursive: true, force: true });
      run.ephemeral_cleanup = "SUCCEEDED";
      run.ephemeral_session_root = null;
      throw error;
    }
    this.processes.set(run.id, { child, ephemeral, secrets });
    run.status = "running";
    run.pid = child.pid ?? null;
    const startedEvent = this.record(run, "validation.started", { pid: run.pid });
    const capture = (stream, source) => {
      let buffer = "";
      stream?.setEncoding?.("utf8");
      stream?.on("data", chunk => {
        buffer += chunk;
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) this.log(run, source, line, secrets).catch(() => {});
      });
    };
    capture(child.stdout, "stdout");
    capture(child.stderr, "stderr");
    child.once("error", error => { run.error = redact(error.message, secrets); });
    child.once("close", (code, signal) => startedEvent.then(() => this.finish({ run, repository, runtimeRoot, requestDescriptor, code, signal })).catch(() => {}));
    await startedEvent;
  }

  async log(run, source, line, secrets) {
    const message = redact(line, secrets);
    if (!message) return;
    await appendFile(join(this.directory(run.id), "runner.log.jsonl"), `${JSON.stringify({ occurred_at: new Date().toISOString(), source, message })}\n`, { encoding: "utf8", mode: 0o600 });
  }

  async validateResultArtifacts({ run, repository, runtimeRoot, requestDescriptor }) {
    if (this.resultValidator) return this.resultValidator({ run: publicRun(run), repository, runtimeRoot, requestDescriptor });
    const validator = join(dirname(repository.config_path), "skills", "dynamic-vulnerability-validator-subagent", "web-xss-runtime-validation", "scripts", "validate-web-xss-runtime-result.mjs");
    await execFileAsync(process.execPath, [
      validator,
      "--request", join(runtimeRoot, requestDescriptor.request_path),
      "--target", join(runtimeRoot, run.audit_id, `${run.finding_id}.target.json`),
      "--result", join(runtimeRoot, run.audit_id, `${run.finding_id}.result.json`),
    ], { cwd: repository.path, encoding: "utf8", timeout: 60_000, maxBuffer: 1024 * 1024 });
  }

  async finish({ run, repository, runtimeRoot, requestDescriptor, code, signal }) {
    const processState = this.processes.get(run.id);
    this.processes.delete(run.id);
    try {
      const resultPath = join(runtimeRoot, run.audit_id, `${run.finding_id}.result.json`);
      let resultPresent = false;
      try { resultPresent = (await stat(resultPath)).isFile(); } catch {}
      run.exit_code = code;
      run.finished_at = new Date().toISOString();
      run.pid = null;
      if (run.status === "cancelling") run.status = "cancelled";
      else if (code === 0 && resultPresent) {
        try {
          await this.validateResultArtifacts({ run, repository, runtimeRoot, requestDescriptor });
          run.result_validation = "PASSED";
          run.status = "completed";
        } catch (error) {
          run.result_validation = "FAILED";
          run.status = "failed";
          run.error = `动态验证结果未通过确定性校验：${genericRedact(error.message)}`;
        }
      } else run.status = "failed";
      if (!resultPresent && run.status === "failed" && !run.error) run.error = "OpenCode 结束时没有生成绑定的动态验证结果。";
      if (signal && !run.error) run.error = `进程由信号 ${signal} 结束。`;
      await this.record(run, `validation.${run.status}`, { exit_code: code, result_present: resultPresent });
    } finally {
      if (processState?.secrets) processState.secrets.fill("");
      try {
        if (processState?.ephemeral?.root) await rm(processState.ephemeral.root, { recursive: true, force: true });
        run.ephemeral_cleanup = "SUCCEEDED";
        run.ephemeral_session_root = null;
        await this.record(run, "validation.ephemeral-session-removed", {});
      } catch (error) {
        run.ephemeral_cleanup = "FAILED";
        run.status = "failed";
        run.error = `临时 OpenCode 会话目录清理失败：${genericRedact(error.message)}`;
        await this.record(run, "validation.ephemeral-session-cleanup-failed", { message: run.error });
      }
    }
  }

  async cancel(id) {
    const run = this.runs.get(id);
    const processState = this.processes.get(id);
    if (!run || !processState || run.status !== "running") throw Object.assign(new Error("该动态验证当前不可取消。"), { statusCode: 409, code: "validation-cancel-not-allowed" });
    run.status = "cancelling";
    await this.record(run, "validation.cancelling", {});
    if (!processState.child.kill("SIGTERM")) throw new Error("取消信号发送失败。");
    return publicRun(run);
  }

  health() {
    return { enabled: this.enabled, active_processes: this.processes.size, ephemeral_sessions: true };
  }

  async shutdown() {
    await this.ready;
    for (const [id, processState] of this.processes) {
      const run = this.runs.get(id);
      if (!run || run.status === "cancelling") continue;
      run.status = "cancelling";
      await this.record(run, "validation.cancelling", { reason: "workbench-shutdown" });
      processState.child.kill("SIGTERM");
    }
  }
}
