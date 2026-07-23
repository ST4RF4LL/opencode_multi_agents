#!/usr/bin/env node

import { readFile, mkdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { contentDigest } from "./function-manifest-cache.mjs";

const PARSER_LANGUAGE = new Map([
  ["joern-python", "python"],
  ["joern-c", "c"],
  ["joern-cpp", "cpp"],
  ["joern-kotlin", "kotlin"],
  ["joern-jvm", "jvm"],
]);

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["root", "audit-id", "scope", "output-dir"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  args.jobs = Number(args.jobs ?? 2);
  if (!Number.isInteger(args.jobs) || args.jobs < 1 || args.jobs > 4) throw new Error("--jobs must be an integer from 1 through 4");
  return args;
}

function runTask(task) {
  return new Promise((resolveTask, rejectTask) => {
    const child = spawn(process.execPath, [task.script, ...task.args], { stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", chunk => stdout.push(chunk));
    child.stderr.on("data", chunk => stderr.push(chunk));
    child.on("error", rejectTask);
    child.on("close", status => {
      const out = Buffer.concat(stdout).toString("utf8");
      const err = Buffer.concat(stderr).toString("utf8");
      if (status !== 0) {
        rejectTask(new Error(`${task.language} function inventory failed (${status})\n${err}\n${out}`));
        return;
      }
      const lastLine = out.trim().split(/\r?\n/).at(-1);
      try {
        resolveTask({ language: task.language, ...JSON.parse(lastLine) });
      } catch {
        rejectTask(new Error(`${task.language} function inventory returned invalid output\n${err}\n${out}`));
      }
    });
  });
}

async function runPool(tasks, jobs) {
  const results = new Array(tasks.length);
  let next = 0;
  async function worker() {
    while (next < tasks.length) {
      const index = next;
      next += 1;
      results[index] = await runTask(tasks[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(jobs, tasks.length) }, worker));
  return results;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = resolve(args.root);
  const scopePath = resolve(args.scope);
  const outputDir = resolve(args["output-dir"]);
  const scope = JSON.parse(await readFile(scopePath, "utf8"));
  if (scope.audit_id !== args["audit-id"] || !scope.complete || scope.manifest_digest !== contentDigest(scope)) {
    throw new Error("Scope manifest is incomplete, modified, or bound to another audit");
  }
  await mkdir(outputDir, { recursive: true });
  const scriptsDir = dirname(fileURLToPath(import.meta.url));
  const common = ["--root", root, "--audit-id", args["audit-id"], "--scope", scopePath];
  const force = args.force === "true" ? ["--force", "true"] : [];
  const tasks = [
    {
      language: "java",
      script: join(scriptsDir, "build-java-function-manifest.mjs"),
      args: [...common, "--output", join(outputDir, "functions-java.json"), ...force],
    },
    {
      language: "javascript",
      script: join(scriptsDir, "build-joern-function-manifest.mjs"),
      args: [...common, "--language", "javascript", "--output", join(outputDir, "functions-javascript.json"), ...force],
    },
    {
      language: "embedded-web",
      script: join(scriptsDir, "build-embedded-web-manifest.mjs"),
      args: [...common, "--output", join(outputDir, "functions-embedded-web.json"), ...force],
    },
  ];
  const parserTags = new Set((scope.files ?? []).map(file => file.function_parser).filter(Boolean));
  for (const [parser, language] of PARSER_LANGUAGE) {
    if (!parserTags.has(parser)) continue;
    tasks.push({
      language,
      script: join(scriptsDir, "build-joern-function-manifest.mjs"),
      args: [...common, "--language", language, "--output", join(outputDir, `functions-${language}.json`), ...force],
    });
  }

  const started = Date.now();
  const manifests = await runPool(tasks, args.jobs);
  process.stdout.write(`${JSON.stringify({ complete: true, jobs: args.jobs, elapsed_ms: Date.now() - started, manifests })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
