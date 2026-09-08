import { open } from "node:fs/promises";

async function readBytes(handle, length, position) {
  const buffer = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const { bytesRead } = await handle.read(buffer, offset, length - offset, position + offset);
    if (!bytesRead) throw new Error("读取期间事件日志被截断，请重试。");
    offset += bytesRead;
  }
  return buffer;
}

// The log is append-only during normal operation. Cache offsets, never payloads.
export class EventLogReader {
  constructor() { this.files = new Map(); }

  async eventsSince(path, sequence = 0, lastEventId = null) {
    const previous = this.files.get(path) ?? Promise.resolve(null);
    const operation = previous.catch(() => null).then(async cached => {
      let handle;
      try { handle = await open(path, "r"); }
      catch (error) { if (error.code === "ENOENT") return { index: null, events: [] }; throw error; }
      try {
        const info = await handle.stat();
        let index = cached?.index;
        if (!index || index.identity !== `${info.dev}:${info.ino}:${info.birthtimeMs}` || info.size < index.size
          || (info.size === index.size && info.mtimeMs !== index.mtime)) {
          index = { identity: `${info.dev}:${info.ino}:${info.birthtimeMs}`, offset: 0, entries: [], size: 0, mtime: 0 };
        }
        // Detect a truncated/recreated tail even if the file has already grown again.
        if (index.anchor?.length) {
          const anchor = await readBytes(handle, index.anchor.length, index.offset - index.anchor.length);
          const head = await readBytes(handle, index.head.length, 0);
          if (!anchor.equals(index.anchor) || !head.equals(index.head)) index = { identity: index.identity, offset: 0, entries: [], size: 0, mtime: 0 };
        }
        const bytes = await readBytes(handle, info.size - index.offset, index.offset);
        let start = 0;
        for (let end = bytes.indexOf(10); end !== -1; end = bytes.indexOf(10, start)) {
          const line = bytes.subarray(start, end).toString("utf8");
          if (line.trim()) {
            const event = JSON.parse(line);
            if (!Number.isSafeInteger(event.sequence) || event.sequence <= (index.entries.at(-1)?.sequence ?? 0)) throw new Error("事件日志序号无效或乱序。");
            index.entries.push({ sequence: event.sequence, id: event.event_id, offset: index.offset + start, end: index.offset + end + 1 });
          }
          start = end + 1;
        }
        index.offset += start; // An incomplete last line will be retried on the next read.
        index.size = info.size;
        index.mtime = info.mtimeMs;
        index.anchor = await readBytes(handle, Math.min(256, index.offset), index.offset - Math.min(256, index.offset));
        index.head = await readBytes(handle, Math.min(256, index.offset), 0);
        const last = lastEventId ? index.entries.find(entry => entry.id === lastEventId) : null;
        const after = last?.sequence ?? sequence;
        let low = 0, high = index.entries.length;
        while (low < high) {
          const mid = (low + high) >>> 1;
          if (index.entries[mid].sequence <= after) low = mid + 1; else high = mid;
        }
        const first = index.entries[low];
        const events = [];
        if (first) {
          const replay = await readBytes(handle, index.offset - first.offset, first.offset);
          for (const line of replay.toString("utf8").split("\n")) if (line.trim()) events.push(JSON.parse(line));
        }
        return { index, events };
      } finally { await handle.close(); }
    });
    this.files.set(path, operation.then(({ index }) => ({ index })));
    // The cache promise may reject independently of the caller's awaited operation.
    this.files.get(path).catch(() => {});
    return (await operation).events;
  }
}
