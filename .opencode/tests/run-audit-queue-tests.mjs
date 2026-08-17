#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditQueueScheduler, QueueSettingsStore } from "../web/dynamic-validation-observatory/audit-queue-scheduler.mjs";

class FakeRunner {
  constructor(audits = []) {
    this.audits = audits.map(audit => ({ ...audit }));
    this.dispatched = [];
    this.ready = Promise.resolve();
  }

  queueSnapshot() {
    return {
      queued: this.audits
        .filter(audit => audit.status === "queued")
        .sort((left, right) => left.created_at.localeCompare(right.created_at) || left.id.localeCompare(right.id))
        .map(audit => ({ id: audit.id, mode: audit.mode ?? "start", created_at: audit.created_at })),
      active_count: this.audits.filter(audit => ["preparing", "recovering", "running", "pausing", "paused", "cancelling"].includes(audit.status)).length,
    };
  }

  async dispatchQueuedAudit(id) {
    const audit = this.audits.find(item => item.id === id);
    assert.equal(audit.status, "queued");
    audit.status = audit.mode === "recover" ? "recovering" : "preparing";
    this.dispatched.push(id);
    audit.status = "running";
    return { ...audit };
  }
}

const root = await mkdtemp(join(tmpdir(), "audit-queue-"));
const settingsPath = join(root, "reports", "platform", "workbench-settings.json");
let now = Date.parse("2026-08-14T00:00:00.000Z");
const timers = [];
const setTimer = (callback, delay) => {
  const timer = { callback, delay, cleared: false, unref() {} };
  timers.push(timer);
  return timer;
};
const clearTimer = timer => { if (timer) timer.cleared = true; };

try {
  const store = new QueueSettingsStore({ path: settingsPath, clock: () => now });
  assert.deepEqual(await store.get(), {
    enabled: false,
    interval_hours: 1,
    concurrency: 1,
    activated_at: null,
    updated_at: null,
    last_dispatch_at: null,
    next_dispatch_at: null,
  });
  assert.equal((await stat(settingsPath)).mode & 0o077, 0);
  await assert.rejects(store.update({ interval_hours: 0 }), error => error.code === "queue-interval-invalid");
  await store.update({ interval_hours: 0.01 });
  assert.equal((await store.get()).interval_hours, 0.01);
  await assert.rejects(store.update({ concurrency: 1.5 }), error => error.code === "queue-concurrency-invalid");
  await store.update({ interval_hours: 0.5, concurrency: 2 });

  const runner = new FakeRunner([
    { id: "audit-003", created_at: "2026-08-14T00:00:03.000Z", status: "queued" },
    { id: "audit-001", created_at: "2026-08-14T00:00:01.000Z", status: "queued" },
    { id: "audit-002", created_at: "2026-08-14T00:00:02.000Z", status: "queued" },
  ]);
  const scheduler = new AuditQueueScheduler({ runner, settingsStore: store, clock: () => now, setTimer, clearTimer });
  await scheduler.ready;
  assert.equal(await scheduler.isEnabled(), false);
  const activated = await scheduler.activate();
  assert.deepEqual(runner.dispatched, ["audit-001", "audit-002"]);
  assert.equal(activated.queued_count, 1);
  assert.equal(activated.active_count, 2);
  assert.equal(activated.available_slots, 0);
  assert.equal(activated.enabled, true);
  assert.equal(timers.at(-1).delay, 30 * 60 * 1000);
  const saved = JSON.parse(await readFile(settingsPath, "utf8"));
  assert.equal(saved.schema_version, 1);
  assert.equal(saved.queue.enabled, true);
  assert.equal(saved.queue.interval_hours, 0.5);
  assert.equal(saved.queue.concurrency, 2);
  assert.match(saved.queue.next_dispatch_at, /^2026-08-14T00:30:00\.000Z$/);

  await scheduler.triggerNow();
  assert.deepEqual(runner.dispatched, ["audit-001", "audit-002"]);

  await scheduler.dispatchAuditNow("audit-003");
  assert.deepEqual(runner.dispatched, ["audit-001", "audit-002", "audit-003"]);
  assert.equal(runner.audits.find(audit => audit.id === "audit-003").status, "running");

  await scheduler.deactivate();
  assert.equal((await store.get()).enabled, false);
  await assert.rejects(scheduler.triggerNow(), error => error.code === "queue-disabled");
  runner.audits.push({ id: "audit-004", created_at: "2026-08-14T00:00:04.000Z", status: "queued" });
  await scheduler.dispatchAuditNow("audit-004");
  assert.deepEqual(runner.dispatched, ["audit-001", "audit-002", "audit-003", "audit-004"]);
  assert.equal(runner.audits.find(audit => audit.id === "audit-004").status, "running");
  assert.equal(timers.at(-1).cleared, true);
  await scheduler.shutdown();
} finally {
  await rm(root, { recursive: true, force: true });
}

process.stdout.write("audit queue tests passed\n");
