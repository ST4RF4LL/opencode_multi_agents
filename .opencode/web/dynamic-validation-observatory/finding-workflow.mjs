import { createHash, randomUUID } from "node:crypto";
import { appendFile, mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

export const FINDING_WORKFLOW_STATES = new Set([
  "unreviewed",
  "confirmed",
  "rejected",
  "insufficient_evidence",
  "awaiting_validation",
  "validated",
  "validation_failed",
  "validation_blocked",
  "reported",
]);

function publicWorkflow(value) {
  if (!value) return null;
  const { idempotency_records, ...result } = value;
  return result;
}

export function emptyFindingWorkflow(resourceId) {
  return { resource_id: resourceId, status: "unreviewed", note: "", version: 0, updated_at: null };
}

export class FindingWorkflowStore {
  constructor({ stateRoot } = {}) {
    this.stateRoot = resolve(stateRoot);
    this.values = new Map();
    this.queues = new Map();
    this.ready = this.initialize();
  }

  directory(resourceId) {
    return join(this.stateRoot, createHash("sha256").update(resourceId).digest("hex"));
  }

  async initialize() {
    await mkdir(this.stateRoot, { recursive: true });
    for (const entry of await readdir(this.stateRoot, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      try {
        const value = JSON.parse(await readFile(join(this.stateRoot, entry.name, "state.json"), "utf8"));
        if (typeof value.resource_id === "string" && FINDING_WORKFLOW_STATES.has(value.status)) this.values.set(value.resource_id, value);
      } catch {
        // Preserve incomplete state directories for operator inspection.
      }
    }
  }

  get(resourceId) {
    return publicWorkflow(this.values.get(resourceId)) ?? emptyFindingWorkflow(resourceId);
  }

  enqueue(resourceId, operation) {
    const previous = this.queues.get(resourceId) ?? Promise.resolve();
    const next = previous.catch(() => {}).then(operation);
    this.queues.set(resourceId, next);
    next.finally(() => { if (this.queues.get(resourceId) === next) this.queues.delete(resourceId); }).catch(() => {});
    return next;
  }

  async persist(value) {
    const directory = this.directory(value.resource_id);
    await mkdir(directory, { recursive: true });
    const temporary = join(directory, `state.${process.pid}.${randomUUID()}.tmp`);
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, join(directory, "state.json"));
  }

  async update({ finding, status, note = "", expectedVersion, idempotencyKey }) {
    await this.ready;
    if (!FINDING_WORKFLOW_STATES.has(status)) throw Object.assign(new Error("漏洞处理状态无效。"), { statusCode: 422, code: "finding-workflow-status-invalid" });
    if (typeof note !== "string" || note.length > 4000) throw Object.assign(new Error("处理备注必须是不超过 4000 字符的文本。"), { statusCode: 422, code: "finding-workflow-note-invalid" });
    if (!idempotencyKey || idempotencyKey.length > 200) throw Object.assign(new Error("缺少有效的 Idempotency-Key。"), { statusCode: 400, code: "idempotency-key-required" });
    return this.enqueue(finding.resource_id, async () => {
      const existing = this.values.get(finding.resource_id);
      const digest = createHash("sha256").update(idempotencyKey).digest("hex");
      const operationDigest = createHash("sha256").update(JSON.stringify({ status, note: note.trim() })).digest("hex");
      const priorOperation = existing?.idempotency_records?.find(record => record.key_digest === digest);
      if (priorOperation) {
        if (priorOperation.operation_digest !== operationDigest) throw Object.assign(new Error("Idempotency-Key 已用于不同的漏洞处理操作。"), { statusCode: 409, code: "idempotency-key-conflict" });
        return publicWorkflow(existing);
      }
      const currentVersion = existing?.version ?? 0;
      if (Number(expectedVersion) !== currentVersion) throw Object.assign(new Error("漏洞处理状态已变化，请刷新后重试。"), { statusCode: 412, code: "version-mismatch" });
      const now = new Date().toISOString();
      const value = {
        resource_id: finding.resource_id,
        repository_id: finding.repository_id,
        audit_id: finding.audit_id,
        finding_id: finding.id,
        status,
        note: note.trim(),
        version: currentVersion + 1,
        updated_at: now,
        idempotency_records: [...(existing?.idempotency_records ?? []), { key_digest: digest, operation_digest: operationDigest }].slice(-100),
      };
      await this.persist(value);
      await appendFile(join(this.directory(value.resource_id), "events.jsonl"), `${JSON.stringify({
        event_id: `evt_${randomUUID()}`,
        resource_id: value.resource_id,
        occurred_at: now,
        type: "finding.workflow.updated",
        previous_status: existing?.status ?? "unreviewed",
        status,
        version: value.version,
        note_present: Boolean(value.note),
      })}\n`, { encoding: "utf8", mode: 0o600 });
      this.values.set(value.resource_id, value);
      return publicWorkflow(value);
    });
  }

  async deleteAudit(auditId, repositoryId) {
    await this.ready;
    const values = [...this.values.values()].filter(value => value.audit_id === auditId && value.repository_id === repositoryId);
    for (const value of values) {
      const queuedWrite = this.queues.get(value.resource_id);
      if (queuedWrite) await queuedWrite;
      await rm(this.directory(value.resource_id), { recursive: true, force: true });
      this.values.delete(value.resource_id);
      this.queues.delete(value.resource_id);
    }
    return values.length;
  }
}
