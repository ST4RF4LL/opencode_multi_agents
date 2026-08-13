#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
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
if (spec.diagnostic_path !== undefined && (typeof spec.diagnostic_path !== "string" || !isAbsolute(spec.diagnostic_path))) {
  fail("tmux launcher spec 的 diagnostic_path 必须是绝对路径。");
}

const environment = {};
for (const [key, value] of Object.entries(spec.environment ?? {})) {
  if ((!/^OPENCODE_[A-Z0-9_]+$/.test(key) && !/^AUDIT_(?:SOURCE|ENGINE|WORKSPACE|REPORTS|TMP)_ROOT$/.test(key)) || typeof value !== "string") fail(`tmux launcher 环境变量非法：${key}`);
  environment[key] = value;
}

const diagnostic = spec.diagnostic_path
  ? createWriteStream(spec.diagnostic_path, { flags: "w", encoding: "utf8", mode: 0o600 })
  : null;
diagnostic?.on("error", () => {});

const child = spawn(spec.command, spec.args, {
  cwd: spec.cwd,
  env: { ...process.env, ...environment },
  stdio: diagnostic ? ["inherit", "pipe", "pipe"] : "inherit",
  shell: false,
  windowsHide: true,
});

if (diagnostic) {
  for (const [stream, output] of [[child.stdout, process.stdout], [child.stderr, process.stderr]]) {
    stream.on("data", chunk => {
      output.write(chunk);
      diagnostic.write(chunk);
    });
  }
}

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) {
  process.on(signal, () => child.kill(signal));
}

let finished = false;
function finish(code, signal, message) {
  if (finished) return;
  finished = true;
  const exit = () => {
    if (signal) process.kill(process.pid, signal);
    else process.exit(code ?? 1);
  };
  if (diagnostic) diagnostic.end(`${message}\n`, exit);
  else exit();
}

child.once("error", error => {
  const message = `tmux launcher 启动失败：${error.message}`;
  process.stderr.write(`${message}\n`);
  finish(1, null, message);
});
child.once("close", (code, signal) => {
  finish(code, signal, `\n[launcher] OpenCode 进程已退出（code=${code ?? "null"}, signal=${signal ?? "none"}）。`);
});
