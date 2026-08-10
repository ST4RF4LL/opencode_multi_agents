import { createHash, randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { spawn } from "node:child_process";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { appendFile, mkdir, open, readFile, readdir, rename, stat, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

const execFileAsync = promisify(execFile);
const AUDIT_ID = /^[a-z0-9][a-z0-9._-]{2,127}$/i;
const REPOSITORY_ID = /^[a-z0-9][a-z0-9._-]{1,63}$/i;
const TERMINAL = new Set(["completed", "failed", "cancelled"]);
const ACTIVE = new Set(["queued", "preparing", "running", "pausing", "paused", "cancelling"]);
const MAX_LOG_LINE = 16 * 1024;
const MAX_LOG_READ_BYTES = 256 * 1024;

function redact(value) {
  return String(value)
    .replace(/(["']?(?:password|passwd|secret|token|authorization|cookie)["']?\s*[:=]\s*["']?)[^\s,"']+/gi, "$1[REDACTED]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[JWT_REDACTED]")
    .slice(0, MAX_LOG_LINE);
}

async function existsFile(path) {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

function normalizeRepository(repository, defaultConfigPath) {
  if (!REPOSITORY_ID.test(repository.id ?? "")) throw new Error(`仓库 ID 非法：${repository.id ?? ""}`);
  const path = resolve(repository.path);
  return {
    id: repository.id,
    name: repository.name ?? basename(path),
    path,
    config_path: resolve(repository.config_path ?? join(path, ".opencode", "opencode.json") ?? defaultConfigPath),
  };
}

async function git(repositoryPath, args) {
  const result = await execFileAsync("git", ["-C", repositoryPath, ...args], {
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 1024 * 1024,
  });
  return result.stdout.trim();
}

function publicRepository(repository, facts = {}) {
  return {
    id: repository.id,
    name: repository.name,
    configured: facts.configured ?? false,
    git_repository: facts.git_repository ?? false,
    branch: facts.branch ?? null,
    commit: facts.commit ?? null,
    dirty: facts.dirty ?? null,
  };
}

function publicAudit(audit) {
  const { idempotency_digest, action_idempotency_digests, ...value } = audit;
  return { ...value };
}

function auditPrompt(audit) {
  return [
    `@security-audit-orchestrator 对当前项目执行一次完整的 repo 级 Tri-Lens 安全审计。`,
    `本次 audit_id 固定为 ${audit.id}，目标提交固定为 ${audit.commit}。`,
    "完成可信结构、威胁建模、多视角漏洞挖掘、覆盖门禁、证据关联、发现裁决和最终中文报告封存。",
    "静态审计完成后可以生成动态验证请求，但不得自行启动动态验证；只有用户另行明确授权并提供 localhost 测试环境时才可执行。",
  ].join("\n");
}

export class AuditRunner extends EventEmitter {
  constructor({ stateRoot, repositories = [], enabled = false, command = "opencode", spawnProcess = spawn } = {}) {
    super();
    this.stateRoot = resolve(stateRoot);
    this.repositories = new Map(repositories.map(repository => {
      const normalized = normalizeRepository(repository);
      return [normalized.id, normalized];
    }));
    this.enabled = enabled;
    this.command = command;
    this.spawnProcess = spawnProcess;
    this.audits = new Map();
    this.processes = new Map();
    this.subscribers = new Map();
    this.writeQueues = new Map();
    this.ready = this.initialize();
  }

  enqueue(id, operation) {
    const prior = this.writeQueues.get(id) ?? Promise.resolve();
    const next = prior.catch(() => {}).then(operation);
    this.writeQueues.set(id, next);
    next.finally(() => { if (this.writeQueues.get(id) === next) this.writeQueues.delete(id); }).catch(() => {});
    return next;
  }

  async initialize() {
    await mkdir(this.stateRoot, { recursive: true });
    const entries = await readdir(this.stateRoot, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      try {
        const audit = JSON.parse(await readFile(join(this.stateRoot, entry.name, "run.json"), "utf8"));
        if (ACTIVE.has(audit.status)) {
          audit.status = "failed";
          audit.error = "平台重启后未发现可恢复的 OpenCode 子进程；请重试该审计。";
          audit.updated_at = new Date().toISOString();
          audit.version = Number(audit.version ?? 0) + 1;
          await this.persist(audit);
        }
        this.audits.set(audit.id, audit);
      } catch {
        // Ignore incomplete state directories; they remain available for operator inspection.
      }
    }
  }

  async repositoryFacts(repository) {
    const configured = await existsFile(repository.config_path);
    try {
      const [commit, branch, dirty] = await Promise.all([
        git(repository.path, ["rev-parse", "HEAD"]),
        git(repository.path, ["branch", "--show-current"]),
        git(repository.path, ["status", "--porcelain", "--untracked-files=no"]),
      ]);
      return { configured, git_repository: true, commit, branch: branch || "DETACHED", dirty: Boolean(dirty) };
    } catch {
      return { configured, git_repository: false, commit: null, branch: null, dirty: null };
    }
  }

  async listRepositories() {
    await this.ready;
    const values = [];
    for (const repository of this.repositories.values()) {
      values.push(publicRepository(repository, await this.repositoryFacts(repository)));
    }
    return values;
  }

  artifactSources() {
    return [...this.repositories.values()].map(repository => ({
      repository_id: repository.id,
      repository_name: repository.name,
      reports_root: join(repository.path, "reports"),
    }));
  }

  runtimeRepositories() {
    return [...this.repositories.values()].map(repository => ({ ...repository }));
  }

  listAudits() {
    return [...this.audits.values()].map(publicAudit).sort((a, b) => b.created_at.localeCompare(a.created_at));
  }

  getAudit(id) {
    const audit = this.audits.get(id);
    return audit ? publicAudit(audit) : null;
  }

  async persist(audit) {
    const directory = join(this.stateRoot, audit.id);
    await mkdir(directory, { recursive: true });
    const temporary = join(directory, `run.${process.pid}.${randomUUID()}.tmp`);
    await writeFile(temporary, `${JSON.stringify(audit, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, join(directory, "run.json"));
  }

  async record(audit, type, data = {}, { bumpVersion = true } = {}) {
    return this.enqueue(audit.id, async () => {
      if (bumpVersion) audit.version += 1;
      audit.updated_at = new Date().toISOString();
      const event = {
        event_id: `evt_${randomUUID()}`,
        audit_id: audit.id,
        sequence: audit.event_sequence + 1,
        occurred_at: audit.updated_at,
        type,
        data,
      };
      audit.event_sequence = event.sequence;
      await this.persist(audit);
      await appendFile(join(this.stateRoot, audit.id, "events.jsonl"), `${JSON.stringify(event)}\n`, { encoding: "utf8", mode: 0o600 });
      this.emit("event", event);
      for (const subscriber of this.subscribers.get(audit.id) ?? []) subscriber(event);
      return event;
    });
  }

  async eventsSince(id, sequence = 0) {
    try {
      const content = await readFile(join(this.stateRoot, id, "events.jsonl"), "utf8");
      return content.split("\n").filter(Boolean).map(line => JSON.parse(line)).filter(event => event.sequence > sequence);
    } catch (error) {
      if (error?.code === "ENOENT") return [];
      throw error;
    }
  }

  async recentLogs(id, limit = 100) {
    const path = join(this.stateRoot, id, "runner.log.jsonl");
    try {
      const info = await stat(path);
      const start = Math.max(0, info.size - MAX_LOG_READ_BYTES);
      const handle = await open(path, "r");
      try {
        const buffer = Buffer.alloc(info.size - start);
        await handle.read(buffer, 0, buffer.length, start);
        const lines = buffer.toString("utf8").split("\n");
        if (start > 0) lines.shift();
        return lines.filter(Boolean).flatMap(line => {
          try { return [JSON.parse(line)]; } catch { return []; }
        }).slice(-Math.min(Math.max(Number(limit) || 100, 1), 200));
      } finally { await handle.close(); }
    } catch (error) {
      if (error?.code === "ENOENT") return [];
      throw error;
    }
  }

  subscribe(id, listener) {
    const listeners = this.subscribers.get(id) ?? new Set();
    listeners.add(listener);
    this.subscribers.set(id, listeners);
    return () => {
      listeners.delete(listener);
      if (listeners.size === 0) this.subscribers.delete(id);
    };
  }

  async createAudit(input, idempotencyKey) {
    await this.ready;
    if (!this.enabled) throw Object.assign(new Error("运行驱动未启用；请用 --enable-runner 启动平台。"), { statusCode: 503, code: "runner-disabled" });
    if (!idempotencyKey || idempotencyKey.length > 200) throw Object.assign(new Error("缺少有效的 Idempotency-Key。"), { statusCode: 400, code: "idempotency-key-required" });
    const repository = this.repositories.get(input.repository_id);
    if (!repository) throw Object.assign(new Error("仓库不在服务端白名单中。"), { statusCode: 422, code: "repository-not-allowed" });
    const id = input.audit_id || `audit-${new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}-${randomUUID().slice(0, 8)}`;
    if (!AUDIT_ID.test(id)) throw Object.assign(new Error("audit_id 格式非法。"), { statusCode: 422, code: "audit-id-invalid" });
    for (const existing of this.audits.values()) {
      if (existing.idempotency_digest === createHash("sha256").update(idempotencyKey).digest("hex")) return publicAudit(existing);
    }
    if (this.audits.has(id)) throw Object.assign(new Error("audit_id 已存在。"), { statusCode: 409, code: "audit-exists" });
    const facts = await this.repositoryFacts(repository);
    if (!facts.git_repository || !facts.configured) throw Object.assign(new Error("白名单仓库缺少 Git 元数据或 .opencode/opencode.json。"), { statusCode: 422, code: "repository-not-ready" });
    if (facts.dirty && input.allow_dirty !== true) throw Object.assign(new Error("仓库存在未提交修改；为保证目标提交可复现，默认拒绝启动。"), { statusCode: 409, code: "repository-dirty" });
    const requestedRef = typeof input.ref === "string" && input.ref ? input.ref : "HEAD";
    if (!/^[a-z0-9][a-z0-9._\/-]{0,199}$/i.test(requestedRef) || requestedRef.includes("..") || requestedRef.includes("@{")) {
      throw Object.assign(new Error("ref 格式非法。"), { statusCode: 422, code: "ref-invalid" });
    }
    const commit = await git(repository.path, ["rev-parse", "--verify", `${requestedRef}^{commit}`]);
    if (commit !== facts.commit) throw Object.assign(new Error("当前工作树不在请求的提交上；平台不会自动 checkout。"), { statusCode: 409, code: "ref-not-checked-out" });
    const now = new Date().toISOString();
    const audit = {
      id,
      name: typeof input.name === "string" && input.name.trim() ? input.name.trim().slice(0, 160) : `仓库级安全审计 · ${repository.name}`,
      repository_id: repository.id,
      repository_name: repository.name,
      commit,
      branch: facts.branch,
      status: "queued",
      version: 1,
      event_sequence: 0,
      created_at: now,
      updated_at: now,
      started_at: null,
      finished_at: null,
      exit_code: null,
      error: null,
      idempotency_digest: createHash("sha256").update(idempotencyKey).digest("hex"),
    };
    this.audits.set(id, audit);
    await this.persist(audit);
    await this.record(audit, "audit.queued", { repository_id: repository.id, commit });
    this.start(audit, repository).catch(async error => {
      audit.status = "failed";
      audit.error = redact(error.message);
      audit.finished_at = new Date().toISOString();
      await this.record(audit, "audit.failed", { message: audit.error });
    });
    return publicAudit(audit);
  }

  async start(audit, repository) {
    audit.status = "preparing";
    audit.started_at = new Date().toISOString();
    await this.record(audit, "audit.preparing", {});
    const child = this.spawnProcess(this.command, [
      "run",
      "--format", "json",
      "--agent", "security-audit-orchestrator",
      "--dir", repository.path,
      "--title", audit.name,
      auditPrompt(audit),
    ], {
      cwd: repository.path,
      env: { ...process.env, OPENCODE_CONFIG: repository.config_path },
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
    });
    this.processes.set(audit.id, child);
    audit.status = "running";
    audit.pid = child.pid ?? null;
    const startedEvent = this.record(audit, "audit.started", { pid: audit.pid });
    const capture = (stream, source) => {
      let buffer = "";
      stream?.setEncoding?.("utf8");
      stream?.on("data", chunk => {
        buffer += chunk;
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) this.recordLog(audit, source, line).catch(() => {});
      });
      stream?.on("end", () => { if (buffer) this.recordLog(audit, source, buffer).catch(() => {}); });
    };
    capture(child.stdout, "stdout");
    capture(child.stderr, "stderr");
    child.once("error", error => {
      audit.error = redact(error.message);
    });
    child.once("close", (code, signal) => {
      startedEvent.then(() => {
        this.processes.delete(audit.id);
        audit.exit_code = code;
        audit.finished_at = new Date().toISOString();
        audit.pid = null;
        if (audit.status === "cancelling") audit.status = "cancelled";
        else if (code === 0) audit.status = "completed";
        else audit.status = "failed";
        if (signal && !audit.error) audit.error = `进程由信号 ${signal} 结束。`;
        return this.record(audit, `audit.${audit.status}`, { exit_code: code, signal: signal ?? null });
      }).catch(() => {});
    });
    await startedEvent;
  }

  async recordLog(audit, source, line) {
    const message = redact(line);
    if (!message) return;
    const entry = { occurred_at: new Date().toISOString(), source, message };
    await appendFile(join(this.stateRoot, audit.id, "runner.log.jsonl"), `${JSON.stringify(entry)}\n`, { encoding: "utf8", mode: 0o600 });
    await this.record(audit, "agent.output", entry, { bumpVersion: false });
  }

  async action(id, action, expectedVersion, idempotencyKey) {
    await this.ready;
    if (!idempotencyKey || idempotencyKey.length > 200) throw Object.assign(new Error("缺少有效的 Idempotency-Key。"), { statusCode: 400, code: "idempotency-key-required" });
    const audit = this.audits.get(id);
    if (!audit) throw Object.assign(new Error("审计不存在。"), { statusCode: 404, code: "audit-not-found" });
    const actionDigest = createHash("sha256").update(idempotencyKey).digest("hex");
    if ((audit.action_idempotency_digests ?? []).includes(actionDigest)) return publicAudit(audit);
    if (Number(expectedVersion) !== audit.version) throw Object.assign(new Error("审计版本已变化，请刷新后重试。"), { statusCode: 412, code: "version-mismatch" });
    const child = this.processes.get(id);
    if (!child || TERMINAL.has(audit.status)) throw Object.assign(new Error("审计当前不可执行该操作。"), { statusCode: 409, code: "action-not-allowed" });
    if (action === "pause" && audit.status === "running") {
      audit.status = "pausing";
      await this.record(audit, "audit.pausing", {});
      if (!child.kill("SIGSTOP")) throw new Error("暂停信号发送失败。");
      audit.status = "paused";
      await this.record(audit, "audit.paused", {});
    } else if (action === "resume" && audit.status === "paused") {
      if (!child.kill("SIGCONT")) throw new Error("恢复信号发送失败。");
      audit.status = "running";
      await this.record(audit, "audit.resumed", {});
    } else if (action === "cancel" && ACTIVE.has(audit.status)) {
      audit.status = "cancelling";
      await this.record(audit, "audit.cancelling", {});
      if (!child.kill("SIGTERM")) throw new Error("取消信号发送失败。");
    } else {
      throw Object.assign(new Error("操作与当前状态不匹配。"), { statusCode: 409, code: "action-not-allowed" });
    }
    audit.action_idempotency_digests = [...(audit.action_idempotency_digests ?? []), actionDigest].slice(-100);
    await this.persist(audit);
    return publicAudit(audit);
  }

  health() {
    return {
      enabled: this.enabled,
      command: this.command,
      active_processes: this.processes.size,
      registered_repositories: this.repositories.size,
      state_root: "server-managed",
    };
  }

  async shutdown() {
    await this.ready;
    for (const [id, child] of this.processes) {
      const audit = this.audits.get(id);
      if (!audit || audit.status === "cancelling") continue;
      audit.status = "cancelling";
      await this.record(audit, "audit.cancelling", { reason: "workbench-shutdown" });
      child.kill("SIGTERM");
    }
  }
}
