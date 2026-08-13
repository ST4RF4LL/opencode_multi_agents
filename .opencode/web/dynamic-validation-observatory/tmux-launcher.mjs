#!/usr/bin/env node

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

const specPath = process.argv[2];
if (!specPath || !isAbsolute(specPath)) fail("tmux launcher 需要绝对 spec 路径。");

let spec;
try {
  spec = JSON.parse(await readFile(specPath, "utf8"));
} catch (error) {
  fail(`无法读取 tmux launcher spec：${error.message}`);
}

if (typeof spec.command !== "string" || !spec.command || !Array.isArray(spec.args) || !spec.args.every(value => typeof value === "string")) {
  fail("tmux launcher spec 的 command/args 非法。");
}
if (typeof spec.cwd !== "string" || !isAbsolute(spec.cwd)) fail("tmux launcher spec 的 cwd 必须是绝对路径。");

const environment = {};
for (const [key, value] of Object.entries(spec.environment ?? {})) {
  if ((!/^OPENCODE_[A-Z0-9_]+$/.test(key) && !/^AUDIT_(?:SOURCE|ENGINE|WORKSPACE|REPORTS|TMP)_ROOT$/.test(key)) || typeof value !== "string") fail(`tmux launcher 环境变量非法：${key}`);
  environment[key] = value;
}

const child = spawn(spec.command, spec.args, {
  cwd: spec.cwd,
  env: { ...process.env, ...environment },
  stdio: "inherit",
  shell: false,
});

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) {
  process.on(signal, () => child.kill(signal));
}

child.once("error", error => fail(`tmux launcher 启动失败：${error.message}`));
child.once("close", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code ?? 1);
});
