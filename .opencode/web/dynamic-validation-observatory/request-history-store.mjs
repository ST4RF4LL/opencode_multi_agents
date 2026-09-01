import { appendFile, mkdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

export class RequestHistoryStore {
  constructor({ stateRoot }) {
    this.stateRoot = resolve(stateRoot);
    this.path = join(this.stateRoot, "http-exchanges.jsonl");
    this.records = new Map();
    this.writeQueue = Promise.resolve();
    this.ready = this.initialize();
  }

  async initialize() {
    await mkdir(this.stateRoot, { recursive: true, mode: 0o700 });
    try {
      const content = await readFile(this.path, "utf8");
      for (const line of content.split("\n").filter(Boolean)) {
        const record = JSON.parse(line);
        this.records.set(record.exchange_id, record);
      }
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }

  async append(record) {
    await this.ready;
    const frozen = structuredClone(record);
    const operation = this.writeQueue.catch(() => {}).then(async () => {
      await appendFile(this.path, `${JSON.stringify(frozen)}\n`, { encoding: "utf8", mode: 0o600 });
      this.records.set(frozen.exchange_id, frozen);
    });
    this.writeQueue = operation;
    await operation;
    return structuredClone(frozen);
  }

  async list({ limit = 100 } = {}) {
    await Promise.all([this.ready, this.writeQueue]);
    return [...this.records.values()].slice(-Math.max(1, Math.min(Number(limit) || 100, 500))).reverse().map(value => structuredClone(value));
  }

  async get(id) {
    await Promise.all([this.ready, this.writeQueue]);
    const value = this.records.get(id);
    return value ? structuredClone(value) : null;
  }
}
