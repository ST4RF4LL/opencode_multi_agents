#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, mkdir, writeFile, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const token = argv[i];
    if (!token?.startsWith("--") || argv[i + 1] == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = argv[i + 1];
  }
  for (const key of ["root", "audit-id", "scope", "output"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  }
  return args;
}

function stableId(value) {
  return `function:${createHash("sha256").update(value).digest("hex").slice(0, 32)}`;
}

function contentDigest(value) {
  const copy = { ...value };
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.status !== 0) {
    throw new Error(`${command} failed (${result.status})\n${result.stderr}\n${result.stdout}`);
  }
  return result;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = resolve(args.root);
  const scopePath = resolve(args.scope);
  const outputPath = resolve(args.output);
  const scope = JSON.parse(await readFile(scopePath, "utf8"));
  if (scope.audit_id !== args["audit-id"]) throw new Error("Scope manifest audit_id mismatch");
  if (!scope.complete) throw new Error("Scope manifest is incomplete");
  if (scope.manifest_digest !== contentDigest(scope)) throw new Error("Scope manifest content digest is invalid");

  const expected = scope.files
    .filter(file => file.function_parser === "javac-java")
    .map(file => file.path)
    .sort();

  const workDir = resolve(dirname(outputPath), ".java-inventory-work");
  const classesDir = resolve(workDir, "classes");
  const listPath = resolve(workDir, "java-files.txt");
  const rawPath = resolve(workDir, "java-inventory.ndjson");
  await rm(workDir, { recursive: true, force: true });
  await mkdir(classesDir, { recursive: true });
  await writeFile(listPath, `${expected.join("\n")}${expected.length ? "\n" : ""}`, "utf8");

  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const helper = resolve(scriptDir, "JavaFunctionInventory.java");
  run("javac", ["-encoding", "UTF-8", "-d", classesDir, helper]);
  if (expected.length > 0) run("java", ["-cp", classesDir, "JavaFunctionInventory", root, listPath, rawPath]);
  else await writeFile(rawPath, "", "utf8");

  const parsedFiles = [];
  const functions = [];
  const diagnostics = [];
  const raw = await readFile(rawPath, "utf8");
  for (const [index, line] of raw.split(/\r?\n/).entries()) {
    if (!line) continue;
    const tab = line.indexOf("\t");
    if (tab < 1) throw new Error(`Malformed helper output line ${index + 1}`);
    const kind = line.slice(0, tab);
    const record = JSON.parse(line.slice(tab + 1));
    if (kind === "FILE") parsedFiles.push(record.path);
    else if (kind === "DIAGNOSTIC") diagnostics.push(record);
    else if (kind === "FUNCTION") {
      const identity = ["java", record.path, record.kind, record.qualified_name, record.signature, record.line_start].join("|");
      functions.push({ function_id: stableId(identity), language: "java", owner_agent: "java-source-auditor", required_lenses: ["sink-driven", "control-driven", "config-driven"], ...record });
    } else throw new Error(`Unknown helper record kind: ${kind}`);
  }

  parsedFiles.sort();
  functions.sort((a, b) => a.path.localeCompare(b.path) || a.line_start - b.line_start || a.qualified_name.localeCompare(b.qualified_name));
  const parsedSet = new Set(parsedFiles);
  const expectedSet = new Set(expected);
  const missingFiles = expected.filter(path => !parsedSet.has(path));
  const unexpectedFiles = parsedFiles.filter(path => !expectedSet.has(path));
  const manifest = {
    schema_version: 1,
    audit_id: args["audit-id"],
    language: "java",
    extractor: { name: "jdk-compiler-ast", helper: "JavaFunctionInventory.java", includes: ["method", "constructor", "lambda", "static-initializer", "instance-initializer"] },
    scope_manifest: scopePath,
    scope_digest: scope.scope_digest,
    expected_files: expected,
    parsed_files: [...new Set(parsedFiles)],
    missing_files: missingFiles,
    unexpected_files: unexpectedFiles,
    diagnostics,
    functions,
    summary: { expected_files: expected.length, parsed_files: new Set(parsedFiles).size, functions: functions.length, diagnostics: diagnostics.length, missing_files: missingFiles.length },
    complete: missingFiles.length === 0 && unexpectedFiles.length === 0 && diagnostics.length === 0,
  };
  manifest.manifest_digest = createHash("sha256").update(JSON.stringify(manifest)).digest("hex");

  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  await rm(workDir, { recursive: true, force: true });
  process.stdout.write(`${JSON.stringify({ output: outputPath, ...manifest.summary, complete: manifest.complete })}\n`);
  if (!manifest.complete) process.exitCode = 2;
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
