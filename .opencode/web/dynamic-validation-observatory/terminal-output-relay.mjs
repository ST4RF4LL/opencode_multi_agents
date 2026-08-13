#!/usr/bin/env node

import { open, readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const specPath = process.argv[2];
if (!specPath || !isAbsolute(specPath)) throw new Error("终端输出中继需要绝对 spec 路径。");

const spec = JSON.parse(await readFile(specPath, "utf8"));
if (!isAbsolute(spec.output_path ?? "") || !isAbsolute(spec.exit_path ?? "")) throw new Error("终端输出中继路径非法。");

let offset = 0;
let stopping = false;
for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) {
  process.once(signal, () => {
    stopping = true;
    process.exit(signal === "SIGTERM" ? 143 : 130);
  });
}

async function relayAvailableOutput() {
  let handle;
  try {
    handle = await open(spec.output_path, "r");
    const info = await handle.stat();
    if (info.size < offset) offset = 0;
    while (offset < info.size) {
      const length = Math.min(64 * 1024, info.size - offset);
      const buffer = Buffer.allocUnsafe(length);
      const { bytesRead } = await handle.read(buffer, 0, length, offset);
      if (!bytesRead) break;
      offset += bytesRead;
      process.stdout.write(buffer.subarray(0, bytesRead));
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  } finally {
    await handle?.close();
  }
}

async function exitState() {
  try {
    return JSON.parse(await readFile(spec.exit_path, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT" || error instanceof SyntaxError) return null;
    throw error;
  }
}

while (!stopping) {
  await relayAvailableOutput();
  const state = await exitState();
  if (state) {
    await relayAvailableOutput();
    if (state.error) process.stderr.write(`${state.error}\n`);
    process.exit(Number.isInteger(state.code) ? state.code : 1);
  }
  await sleep(100);
}
