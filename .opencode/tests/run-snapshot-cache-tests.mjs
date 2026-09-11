import assert from "node:assert/strict";
import { createSnapshotCache } from "../web/dynamic-validation-observatory/snapshot-cache.mjs";

const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
let now = 0;
let calls = 0;
let next = deferred();
const cache = createSnapshotCache(() => { calls += 1; return next.promise; }, { ttlMs: 100, now: () => now });
const first = cache.get({ allowStale: true });
const second = cache.get({ allowStale: true });
assert.equal(first, second);
await Promise.resolve();
assert.equal(calls, 1);
next.resolve({ version: 1 });
await first;
assert.equal((await cache.get({ allowStale: true })).version, 1);
assert.equal(calls, 1);

now = 101;
next = deferred();
// An expired display read must complete without waiting for the scanner.
assert.equal((await cache.get({ allowStale: true })).version, 1);
assert.equal((await cache.get({ allowStale: true })).version, 1);
assert.equal(calls, 2);
const verification = cache.get();
next.resolve({ version: 2 });
assert.equal((await verification).version, 2);

now = 202;
const obsolete = deferred();
next = obsolete;
await cache.get({ allowStale: true });
const obsoleteRead = cache.get();
cache.invalidate();
next = deferred();
const afterMutation = cache.get({ allowStale: true });
await Promise.resolve();
next.resolve({ version: 3 });
await afterMutation;
obsolete.resolve({ version: 0 });
await obsoleteRead;
assert.equal((await cache.get({ allowStale: true })).version, 3);

cache.invalidate();
next = deferred();
const failure = cache.get();
await Promise.resolve();
next.reject(new Error("scanner failed"));
await assert.rejects(failure, /scanner failed/);
next = deferred();
const retry = cache.get();
next.resolve({ version: 4 });
assert.equal((await retry).version, 4);
console.log("快照并发合并、后台刷新、写入失效及失败重试检查通过。");
