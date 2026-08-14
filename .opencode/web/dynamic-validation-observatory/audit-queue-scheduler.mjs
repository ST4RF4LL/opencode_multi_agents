import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const SCHEMA_VERSION = 1;
const DEFAULT_QUEUE = Object.freeze({
  enabled: false,
  interval_hours: 1.0,
  concurrency: 1,
  activated_at: null,
  updated_at: null,
  last_dispatch_at: null,
  next_dispatch_at: null,
});
const MAX_TIMEOUT_MS = 2_147_000_000;

function clone(value) {
  return structuredClone(value);
}

function nowIso(clock) {
  return new Date(clock()).toISOString();
}

function invalid(message, code = "queue-settings-invalid") {
  return Object.assign(new Error(message), { statusCode: 422, code });
}

function normalizeInterval(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw invalid("队列间隔必须是大于 0 的小时数。", "queue-interval-invalid");
  }
  return value;
}

function normalizeConcurrency(value) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw invalid("并发必须是大于 0 的整数。", "queue-concurrency-invalid");
  }
  return value;
}

function normalizeTimestamp(value, label) {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw invalid(`${label}不是有效时间。`, "queue-settings-invalid");
  }
  return value;
}

function normalizeQueue(value = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid("队列设置必须是对象。", "queue-settings-invalid");
  }
  if (value.enabled !== undefined && typeof value.enabled !== "boolean") {
    throw invalid("队列启用状态必须是布尔值。", "queue-settings-invalid");
  }
  return {
    enabled: value.enabled ?? DEFAULT_QUEUE.enabled,
    interval_hours: normalizeInterval(value.interval_hours ?? DEFAULT_QUEUE.interval_hours),
    concurrency: normalizeConcurrency(value.concurrency ?? DEFAULT_QUEUE.concurrency),
    activated_at: normalizeTimestamp(value.activated_at, "激活时间"),
    updated_at: normalizeTimestamp(value.updated_at, "更新时间"),
    last_dispatch_at: normalizeTimestamp(value.last_dispatch_at, "上次调度时间"),
    next_dispatch_at: normalizeTimestamp(value.next_dispatch_at, "下次调度时间"),
  };
}

function normalizeDocument(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid("队列设置文件不是有效 JSON 对象。", "queue-settings-invalid");
  }
  if (value.schema_version !== undefined && value.schema_version !== SCHEMA_VERSION) {
    throw invalid(`不支持的队列设置版本：${value.schema_version}。`, "queue-settings-version-invalid");
  }
  return { schema_version: SCHEMA_VERSION, queue: normalizeQueue(value.queue ?? value) };
}

export class QueueSettingsStore {
  constructor({ path, clock = () => Date.now() } = {}) {
    if (!path) throw new Error("队列设置路径不能为空。");
    this.path = resolve(path);
    this.clock = clock;
    this.document = null;
    this.writes = Promise.resolve();
    this.ready = this.initialize();
  }

  async initialize() {
    await mkdir(dirname(this.path), { recursive: true });
    try {
      this.document = normalizeDocument(JSON.parse(await readFile(this.path, "utf8")));
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      this.document = { schema_version: SCHEMA_VERSION, queue: clone(DEFAULT_QUEUE) };
      await this.persist();
    }
  }

  async persist() {
    const temporary = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temporary, `${JSON.stringify(this.document, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, this.path);
  }

  async mutate(mutator) {
    await this.ready;
    const operation = this.writes.catch(() => {}).then(async () => {
      const next = clone(this.document);
      await mutator(next.queue);
      next.queue = normalizeQueue(next.queue);
      next.schema_version = SCHEMA_VERSION;
      this.document = next;
      await this.persist();
      return clone(this.document.queue);
    });
    this.writes = operation;
    return operation;
  }

  async get() {
    await this.ready;
    return clone(this.document.queue);
  }

  async update({ interval_hours, concurrency } = {}) {
    if (interval_hours === undefined && concurrency === undefined) {
      throw invalid("至少提供队列间隔或并发之一。", "queue-settings-empty");
    }
    return this.mutate(queue => {
      if (interval_hours !== undefined) queue.interval_hours = normalizeInterval(interval_hours);
      if (concurrency !== undefined) queue.concurrency = normalizeConcurrency(concurrency);
      queue.updated_at = nowIso(this.clock);
    });
  }

  async activate() {
    return this.mutate(queue => {
      const now = nowIso(this.clock);
      queue.enabled = true;
      queue.activated_at = now;
      queue.updated_at = now;
      queue.next_dispatch_at = null;
    });
  }

  async deactivate() {
    return this.mutate(queue => {
      queue.enabled = false;
      queue.updated_at = nowIso(this.clock);
      queue.next_dispatch_at = null;
    });
  }

  async schedule({ lastDispatchAt, nextDispatchAt } = {}) {
    return this.mutate(queue => {
      queue.last_dispatch_at = normalizeTimestamp(lastDispatchAt, "上次调度时间");
      queue.next_dispatch_at = normalizeTimestamp(nextDispatchAt, "下次调度时间");
    });
  }
}

export class AuditQueueScheduler {
  constructor({ runner, settingsStore, clock = () => Date.now(), setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
    if (!runner || typeof runner.queueSnapshot !== "function" || typeof runner.dispatchQueuedAudit !== "function") {
      throw new Error("队列调度器需要支持队列快照和任务启动的 AuditRunner。");
    }
    if (!settingsStore) throw new Error("队列调度器需要设置存储。");
    this.runner = runner;
    this.settingsStore = settingsStore;
    this.clock = clock;
    this.setTimer = setTimer;
    this.clearTimer = clearTimer;
    this.timer = null;
    this.dispatches = Promise.resolve();
    this.stopped = false;
    this.ready = this.initialize();
  }

  async initialize() {
    await Promise.all([this.runner.ready, this.settingsStore.ready]);
    const queue = await this.settingsStore.get();
    if (!queue.enabled) return;
    const nextAt = Date.parse(queue.next_dispatch_at ?? "");
    if (!Number.isFinite(nextAt) || nextAt <= this.clock()) {
      await this.enqueueDispatch();
    } else {
      this.arm(nextAt);
    }
  }

  arm(timestamp) {
    if (this.stopped) return;
    if (this.timer) this.clearTimer(this.timer);
    const delay = Math.max(0, Math.min(timestamp - this.clock(), MAX_TIMEOUT_MS));
    this.timer = this.setTimer(() => {
      this.timer = null;
      this.onTimer().catch(() => {});
    }, delay);
    this.timer?.unref?.();
  }

  async onTimer() {
    if (this.stopped) return;
    const queue = await this.settingsStore.get();
    if (!queue.enabled) return;
    const nextAt = Date.parse(queue.next_dispatch_at ?? "");
    if (Number.isFinite(nextAt) && nextAt > this.clock()) {
      this.arm(nextAt);
      return;
    }
    await this.dispatchNow();
  }

  async scheduleFrom(queue, { immediate = false } = {}) {
    if (!queue.enabled || this.stopped) return;
    if (immediate) {
      await this.dispatchNow();
      return;
    }
    const last = Date.parse(queue.last_dispatch_at ?? "");
    const base = Number.isFinite(last) ? last : this.clock();
    const next = base + queue.interval_hours * 60 * 60 * 1000;
    const persisted = await this.settingsStore.schedule({
      lastDispatchAt: queue.last_dispatch_at,
      nextDispatchAt: new Date(next).toISOString(),
    });
    this.arm(Date.parse(persisted.next_dispatch_at));
  }

  async isEnabled() {
    await this.ready;
    return (await this.settingsStore.get()).enabled;
  }

  async enqueueNewAudit() {
    await this.ready;
    const queue = await this.settingsStore.get();
    if (!queue.enabled) return false;
    await this.scheduleFrom(queue);
    return true;
  }

  async activate() {
    await this.ready;
    await this.settingsStore.activate();
    await this.dispatchNow();
    return this.snapshot();
  }

  async deactivate() {
    await this.ready;
    if (this.timer) this.clearTimer(this.timer);
    this.timer = null;
    await this.settingsStore.deactivate();
    return this.snapshot();
  }

  async updateSettings(input) {
    await this.ready;
    const queue = await this.settingsStore.update(input);
    if (queue.enabled) await this.scheduleFrom(queue);
    return this.snapshot();
  }

  async dispatchNow() {
    await this.ready;
    return this.enqueueDispatch();
  }

  async enqueueDispatch() {
    const operation = this.dispatches.catch(() => {}).then(async () => {
      if (this.stopped) return;
      const queue = await this.settingsStore.get();
      if (!queue.enabled) return;
      const snapshot = this.runner.queueSnapshot();
      const capacity = Math.max(0, queue.concurrency - snapshot.active_count);
      for (const audit of snapshot.queued.slice(0, capacity)) {
        await this.runner.dispatchQueuedAudit(audit.id);
      }
      const dispatchedAt = nowIso(this.clock);
      const nextAt = new Date(this.clock() + queue.interval_hours * 60 * 60 * 1000).toISOString();
      const persisted = await this.settingsStore.schedule({ lastDispatchAt: dispatchedAt, nextDispatchAt: nextAt });
      this.arm(Date.parse(persisted.next_dispatch_at));
    });
    this.dispatches = operation;
    return operation;
  }

  async snapshot() {
    await this.ready;
    const queue = await this.settingsStore.get();
    const runner = this.runner.queueSnapshot();
    return {
      ...queue,
      queued_count: runner.queued.length,
      active_count: runner.active_count,
      available_slots: Math.max(0, queue.concurrency - runner.active_count),
    };
  }

  async shutdown() {
    this.stopped = true;
    if (this.timer) this.clearTimer(this.timer);
    this.timer = null;
    await this.dispatches.catch(() => {});
  }
}
