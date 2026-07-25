#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { delimiter, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { contentDigest } from "./function-manifest-cache.mjs";

const PROBES = {
  "javac-java": { kind: "command", command: "javac", args: ["-version"] },
  "joern-js": { kind: "joern", language: "javascript", extension: ".js", source: "function capabilityProbe() { return 1; }\n" },
  "joern-python": { kind: "joern", language: "python", extension: ".py", source: "def capability_probe():\n    return 1\n" },
  "joern-c": { kind: "joern", language: "c", extension: ".c", source: "int capability_probe(void) { return 1; }\n" },
  "joern-cpp": { kind: "joern", language: "c", extension: ".cpp", source: "int capability_probe() { return 1; }\n" },
  "joern-kotlin": { kind: "joern", language: "kotlin", extension: ".kt", source: "fun capabilityProbe(): Int = 1\n" },
  "joern-jvm": { kind: "joern", language: "java", extension: ".java", source: "class CapabilityProbe { int probe() { return 1; } }\n" },
  "embedded-web": { kind: "builtin" },
};

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["root", "audit-id", "scope", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

function diagnostic(result) {
  const combined = `${result.error?.message ?? ""}\n${result.stderr ?? ""}\n${result.stdout ?? ""}`.replace(/\s+/g, " ").trim();
  return combined.slice(0, 600) || "probe-command-failed";
}

async function loadToolchain(root) {
  let configured = {};
  try {
    const config = JSON.parse(await readFile(join(root, ".opencode", "opencode.json"), "utf8"));
    configured = config?.mcp?.joern?.environment ?? {};
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const basePath = process.env.PATH || "/usr/bin:/bin";
  return {
    joernParseBin: process.env.JOERN_PARSE_BIN || configured.JOERN_PARSE_BIN || "joern-parse",
    environment: {
      ...process.env,
      PATH: [process.env.JOERN_GNUBIN || configured.JOERN_GNUBIN, process.env.JOERN_JAVA_BIN || configured.JOERN_JAVA_BIN, ...basePath.split(delimiter)].filter(Boolean).join(delimiter),
    },
  };
}

async function probe(parser, toolchain) {
  const probe = PROBES[parser];
  if (!probe) return { parser, status: "unavailable", reason: "no-configured-capability-probe" };
  if (probe.kind === "builtin") return { parser, status: "available", reason: "built-in-extractor" };
  if (probe.kind === "command") {
    const result = spawnSync(probe.command, probe.args, { encoding: "utf8" });
    return result.status === 0
      ? { parser, status: "available", reason: "command-probe-succeeded" }
      : { parser, status: "unavailable", reason: diagnostic(result) };
  }
  const directory = await mkdtemp(join(tmpdir(), "opencode-parser-probe-"));
  try {
    const source = join(directory, `probe${probe.extension}`);
    const cpg = join(directory, "probe.cpg.bin");
    const workspace = join(directory, "workspace");
    await writeFile(source, probe.source, "utf8");
    await mkdir(workspace, { recursive: true });
    const result = spawnSync(toolchain.joernParseBin, [source, "-o", cpg, "--language", probe.language], {
      encoding: "utf8",
      env: { ...toolchain.environment, JOERN_WORKSPACE: workspace },
    });
    let output = null;
    try { output = await stat(cpg); } catch { output = null; }
    return result.status === 0 && output?.size > 0
      ? { parser, status: "available", reason: "frontend-smoke-probe-succeeded", frontend_language: probe.language }
      : { parser, status: "unavailable", reason: diagnostic(result), frontend_language: probe.language };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = resolve(args.root);
  const scope = JSON.parse(await readFile(resolve(args.scope), "utf8"));
  if (scope.audit_id !== args["audit-id"] || !scope.complete || scope.manifest_digest !== contentDigest(scope)) {
    throw new Error("Scope manifest is incomplete, modified, or bound to another audit");
  }
  const parserFiles = new Map();
  for (const file of scope.files ?? []) {
    if (!file.function_inventory_required || !file.function_parser) continue;
    const files = parserFiles.get(file.function_parser) ?? [];
    files.push(file.path);
    parserFiles.set(file.function_parser, files);
  }
  const toolchain = await loadToolchain(root);
  const capabilities = [];
  for (const parser of [...parserFiles.keys()].sort()) {
    const capability = await probe(parser, toolchain);
    capabilities.push({ ...capability, files: parserFiles.get(parser).sort() });
  }
  const manifest = {
    schema_version: 1,
    audit_id: args["audit-id"],
    scope_digest: scope.scope_digest,
    capabilities,
    complete: capabilities.every(item => item.status === "available"),
  };
  manifest.manifest_digest = createHash("sha256").update(JSON.stringify(manifest)).digest("hex");
  const output = resolve(args.output);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output, complete: manifest.complete, available: capabilities.filter(item => item.status === "available").map(item => item.parser), unavailable: capabilities.filter(item => item.status === "unavailable").map(item => item.parser), manifest_digest: manifest.manifest_digest })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
