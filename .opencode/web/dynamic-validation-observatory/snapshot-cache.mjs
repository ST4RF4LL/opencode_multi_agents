// One bounded snapshot; expired reads reuse it while one refresh runs.
export function createSnapshotCache(build, { ttlMs = 3000, now = Date.now } = {}) {
  let cached;
  let refreshedAt = 0;
  let generation = 0;
  let pending = null;
  function refresh() {
    if (pending) return pending;
    const startedGeneration = generation;
    const operation = Promise.resolve().then(build).then(value => {
      if (generation === startedGeneration) {
        cached = value;
        refreshedAt = now();
      }
      return value;
    });
    pending = operation;
    operation.then(clear, clear);
    function clear() { if (pending === operation) pending = null; }
    return operation;
  }
  return {
    get({ allowStale = false } = {}) {
      if (!allowStale || cached === undefined) return refresh();
      if (now() - refreshedAt >= ttlMs) refresh().catch(() => {});
      return Promise.resolve(cached);
    },
    invalidate() {
      generation += 1;
      cached = undefined;
      pending = null;
    },
  };
}
