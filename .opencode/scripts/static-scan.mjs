#!/usr/bin/env node

import { mkdir, readFile, readdir, rm } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { probeEngines, resolveAllowedPath, resolveWorkspacePath, runProcess, runSemgrepScan } from "./semgrep-core.mjs";
import { aggregateStaticRuns, digestPath, writeStaticRun, verifyStaticRun } from "./static-artifacts.mjs";
import { resolveExecutablePath } from "../web/dynamic-validation-observatory/executable-resolution.mjs";

const ENGINES = new Set(["auto", "opengrep", "semgrep", "gitleaks", "osv-scanner"]);
const MAX_OUTPUT_BYTES = 16 * 1024;
const NATIVE_ADAPTERS = new Map([
  ["gitleaks", {
    id: "gitleaks",
    capability: "secret_scan",
    command: () => process.env.GITLEAKS_BIN ?? "gitleaks",
    buildArgs: (target, output) => ["detect", "--source", target, "--no-banner", "--redact", "--report-format", "sarif", "--report-path", output],
    options: { recursive: true, redacted: true },
  }],
  ["osv-scanner", {
    id: "osv-scanner",
    capability: "dependency_scan",
    command: () => process.env.OSV_SCANNER_BIN ?? "osv-scanner",
    buildArgs: (target, output) => ["scan", "source", "-r", target, "--format", "sarif", "--output", output],
    options: { recursive: true, redacted: false },
  }],
]);

function usage() {
  return `Usage:
  node .opencode/scripts/static-scan.mjs doctor
  node .opencode/scripts/static-scan.mjs plan --target PATH
  node .opencode/scripts/static-scan.mjs run --engine ENGINE --audit-id ID --session-id ID --agent-name NAME --target PATH [--rule PATH ...]
  node .opencode/scripts/static-scan.mjs verify --run-dir PATH
  node .opencode/scripts/static-scan.mjs aggregate --audit-id ID --output reports/sarif/FILE.sarif

Engines: auto, opengrep, semgrep, gitleaks, osv-scanner
Environment: OPENGREP_BIN, SEMGREP_BIN, GITLEAKS_BIN, OSV_SCANNER_BIN and AUDIT_*_ROOT
`;
}

function emit(value, stream = process.stdout) {
  const bytes = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(bytes) > MAX_OUTPUT_BYTES) throw new Error("CLI summary exceeded 16 KiB");
  stream.write(bytes);
}

function parse(args) {
  const result = { rules: [], engine: "auto" };
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (["-h", "--help"].includes(option)) return { help: true };
    if (!option.startsWith("--") || args[index + 1] === undefined) throw new Error(`Invalid option: ${option}`);
    const value = args[++index];
    if (value.includes("\0") || Buffer.byteLength(value) > 4096) throw new Error(`Invalid value for ${option}`);
    if (option === "--rule") result.rules.push(value);
    else if (option === "--audit-id") result.auditId = value;
    else if (option === "--session-id") result.sessionId = value;
    else if (option === "--agent-name") result.agentName = value;
    else if (option === "--target") result.target = value;
    else if (option === "--engine") result.engine = value;
    else if (option === "--run-dir") result.runDir = value;
    else if (option === "--output") result.output = value;
    else throw new Error(`Unknown option: ${option}`);
  }
  if (!ENGINES.has(result.engine)) throw new Error(`Unsupported engine: ${result.engine}`);
  return result;
}

async function probeTool(id, command, workspaceRoot, args = ["--version"]) {
  try {
    if (args === null) {
      const resolved = await resolveExecutablePath(command);
      return resolved ? { id, available: true, version: null } : { id, available: false, version: null, error: "executable not found" };
    }
    const result = await runProcess(command, args, { cwd: workspaceRoot, timeoutMs: 10_000 });
    return { id, available: result.code === 0, version: (result.stdout.trim() || result.stderr.trim()).split(/\r?\n/)[0]?.slice(0, 240) ?? null };
  } catch (error) {
    return { id, available: false, version: null, error: String(error.message).slice(0, 500) };
  }
}

async function doctor(workspaceRoot) {
  const pattern = await probeEngines({ workspaceRoot });
  const [gitleaks, osv, java, javac, joern, joernParse] = await Promise.all([
    ...[...NATIVE_ADAPTERS.values()].map(adapter => probeTool(adapter.id, adapter.command(), workspaceRoot)),
    probeTool("java", process.env.JAVA_HOME ? join(process.env.JAVA_HOME, "bin", process.platform === "win32" ? "java.exe" : "java") : "java", workspaceRoot),
    probeTool("javac", process.env.JAVA_HOME ? join(process.env.JAVA_HOME, "bin", process.platform === "win32" ? "javac.exe" : "javac") : "javac", workspaceRoot),
    probeTool("joern", process.env.JOERN_BIN ?? "joern", workspaceRoot, null),
    probeTool("joern-parse", process.env.JOERN_PARSE_BIN ?? "joern-parse", workspaceRoot, ["--list-languages"]),
  ]);
  const deepReady = java.available && joern.available && joernParse.available;
  const components = [...pattern.map(({ command: _command, ...item }) => item), gitleaks, osv, java, javac, joern, joernParse];
  return {
    complete: true,
    capabilities: [
      { id: "source_pattern_scan", status: pattern.some(item => item.available) ? "ready" : "blocked", engines: ["opengrep", "semgrep"] },
      { id: "secret_scan", status: gitleaks.available ? "ready" : "skipped", engines: ["gitleaks"] },
      { id: "dependency_scan", status: osv.available ? "ready" : "skipped", engines: ["osv-scanner"] },
      { id: "function_inventory", status: javac.available || joernParse.available ? "provider_dependent" : "skipped", engines: ["javac", "joern-parse", "builtin"] },
      { id: "deep_dataflow", status: deepReady ? "ready" : "skipped", engines: ["joern"] },
    ],
    components,
  };
}

async function collectNames(root, limit = 20_000) {
  const names = [];
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (names.length >= limit) return;
      const path = join(directory, entry.name);
      if (entry.isDirectory() && !entry.isSymbolicLink() && ![".git", "node_modules", "vendor", "reports", "tmp"].includes(entry.name)) await walk(path);
      else if (entry.isFile()) names.push(entry.name.toLowerCase());
    }
  }
  await walk(root);
  return names;
}

async function plan(workspaceRoot, targetInput) {
  const sourceRoot = process.env.AUDIT_SOURCE_ROOT ? resolve(process.env.AUDIT_SOURCE_ROOT) : workspaceRoot;
  const target = process.env.AUDIT_SOURCE_ROOT
    ? await resolveAllowedPath(workspaceRoot, targetInput, [sourceRoot], { label: "Scan target" })
    : await resolveWorkspacePath(workspaceRoot, targetInput);
  const [health, names] = await Promise.all([doctor(workspaceRoot), collectNames(target)]);
  const dependencyMarkers = new Set(["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt", "poetry.lock", "go.mod", "cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts"]);
  const applicableDependencies = names.some(name => dependencyMarkers.has(name));
  const capability = id => health.capabilities.find(item => item.id === id);
  return {
    complete: true,
    target: relative(sourceRoot, target).replaceAll("\\", "/") || ".",
    target_digest: await digestPath(target, { excludedPaths: [process.env.AUDIT_REPORTS_ROOT ?? join(workspaceRoot, "reports"), process.env.AUDIT_TMP_ROOT ?? join(workspaceRoot, "tmp")] }),
    scans: [
      { capability: "source_pattern_scan", required: true, status: capability("source_pattern_scan").status === "ready" ? "PLANNED" : "GAP" },
      { capability: "secret_scan", required: false, status: capability("secret_scan").status === "ready" ? "PLANNED" : "SKIPPED" },
      { capability: "dependency_scan", required: false, status: !applicableDependencies ? "NOT_APPLICABLE" : capability("dependency_scan").status === "ready" ? "PLANNED" : "SKIPPED" },
      { capability: "deep_dataflow", required: false, status: "SKIPPED", reason: "Joern is an optional deep-analysis provider" },
    ],
  };
}

function sanitizeSarif(sarif, workspaceRoot) {
  if (sarif?.version !== "2.1.0" || !Array.isArray(sarif.runs)) throw new Error("Scanner did not produce SARIF 2.1.0");
  for (const run of sarif.runs) {
    for (const result of run.results ?? []) {
      for (const location of result.locations ?? []) {
        const artifact = location.physicalLocation?.artifactLocation;
        if (!artifact?.uri || !isAbsolute(artifact.uri)) continue;
        const rel = relative(workspaceRoot, resolve(artifact.uri));
        if (rel === ".." || rel.startsWith("../") || rel.startsWith("..\\")) throw new Error("SARIF artifact URI escapes workspace");
        artifact.uri = rel.replaceAll("\\", "/");
      }
    }
  }
  return sarif;
}

async function runNative({ workspaceRoot, options }) {
  for (const key of ["auditId", "sessionId", "agentName", "target"]) if (!options[key]) throw new Error(`--${key.replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`)} is required`);
  const splitWorkspace = Boolean(process.env.AUDIT_SOURCE_ROOT && process.env.AUDIT_REPORTS_ROOT && process.env.AUDIT_TMP_ROOT);
  const sourceRoot = splitWorkspace ? resolve(process.env.AUDIT_SOURCE_ROOT) : workspaceRoot;
  const reportsRoot = splitWorkspace ? resolve(process.env.AUDIT_REPORTS_ROOT) : join(workspaceRoot, "reports");
  const tmpRoot = splitWorkspace ? resolve(process.env.AUDIT_TMP_ROOT) : join(workspaceRoot, "tmp");
  const target = splitWorkspace
    ? await resolveAllowedPath(workspaceRoot, options.target, [sourceRoot], { label: "Scan target" })
    : await resolveWorkspacePath(workspaceRoot, options.target);
  const targetDigest = await digestPath(target, { excludedPaths: [reportsRoot, tmpRoot] });
  const temporaryDirectory = join(tmpRoot, options.auditId, "static-scan", `${options.engine}-${process.pid}-${Date.now()}`);
  await mkdir(temporaryDirectory, { recursive: true });
  const nativeSarif = join(temporaryDirectory, "native.sarif");
  const adapter = NATIVE_ADAPTERS.get(options.engine);
  if (!adapter) throw new Error(`No native SARIF adapter for ${options.engine}`);
  const command = adapter.command();
  const args = adapter.buildArgs(target, nativeSarif);
  const capability = adapter.capability;
  try {
    const result = await runProcess(command, args, { cwd: workspaceRoot, timeoutMs: 300_000 });
    if (![0, 1].includes(result.code)) throw new Error(`${options.engine} failed with exit ${result.code}: ${result.stderr.slice(-2000)}`);
    const sarif = sanitizeSarif(JSON.parse(await readFile(nativeSarif, "utf8")), sourceRoot);
    const findings = sarif.runs.reduce((sum, run) => sum + (run.results?.length ?? 0), 0);
    const version = sarif.runs[0]?.tool?.driver?.version ?? "unknown";
    const immutable = await writeStaticRun({
      reportsRoot,
      auditId: options.auditId,
      identity: {
        schema_version: "static-scan-identity.v1",
        capability,
        engine: options.engine,
        engine_version: version,
        target_path: relative(sourceRoot, target).replaceAll("\\", "/") || ".",
        target_digest: targetDigest,
        rule_pack_digest: null,
        options: adapter.options,
      },
      sarif,
      summary: { status: "SUCCESS", engine: options.engine, engine_version: version, findings, errors: 0, requested_rules: [], executed_rules: [], skipped_rules: [] },
    });
    return { complete: true, engine: options.engine, capability, findings, scan_run_id: immutable.scan_run_id, run_manifest_path: splitWorkspace ? `reports/${relative(reportsRoot, immutable.manifest_path).replaceAll("\\", "/")}` : relative(workspaceRoot, immutable.manifest_path).replaceAll("\\", "/") };
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}

async function run(workspaceRoot, options) {
  if (["gitleaks", "osv-scanner"].includes(options.engine)) return runNative({ workspaceRoot, options });
  if (options.rules.length === 0) throw new Error("At least one --rule is required for Semgrep/OpenGrep");
  return runSemgrepScan({ workspaceRoot, auditId: options.auditId, sessionId: options.sessionId, agentName: options.agentName, targetPath: options.target, rulePaths: options.rules, engine: options.engine });
}

async function main() {
  const [command, ...rawArgs] = process.argv.slice(2);
  if (!command || ["-h", "--help"].includes(command)) return process.stdout.write(usage());
  const options = parse(rawArgs);
  if (options.help) return process.stdout.write(usage());
  const workspaceRoot = resolve(process.cwd());
  if (command === "doctor") {
    if (rawArgs.length) throw new Error("doctor does not accept arguments");
    return emit(await doctor(workspaceRoot));
  }
  if (command === "plan") {
    if (!options.target) throw new Error("--target is required");
    return emit(await plan(workspaceRoot, options.target));
  }
  if (command === "run") return emit(await run(workspaceRoot, options));
  if (command === "verify") {
    if (!options.runDir) throw new Error("--run-dir is required");
    return emit(await verifyStaticRun(await resolveWorkspacePath(workspaceRoot, options.runDir)));
  }
  if (command === "aggregate") {
    if (!options.auditId || !options.output) throw new Error("--audit-id and --output are required");
    const splitWorkspace = Boolean(process.env.AUDIT_REPORTS_ROOT);
    const reportsRoot = splitWorkspace ? resolve(process.env.AUDIT_REPORTS_ROOT) : join(workspaceRoot, "reports");
    if (splitWorkspace) await mkdir(join(reportsRoot, "sarif"), { recursive: true });
    const requestedOutput = splitWorkspace && options.output.replaceAll("\\", "/").startsWith("reports/")
      ? resolve(reportsRoot, options.output.replaceAll("\\", "/").slice("reports/".length))
      : options.output;
    const output = splitWorkspace
      ? await resolveAllowedPath(workspaceRoot, requestedOutput, [join(reportsRoot, "sarif")], { mustExist: false, label: "SARIF output" })
      : await resolveWorkspacePath(workspaceRoot, requestedOutput, { mustExist: false });
    return emit(await aggregateStaticRuns({ reportsRoot, auditId: options.auditId, outputPath: output }));
  }
  throw new Error(`Unknown command: ${command}`);
}

main().catch(error => {
  emit({ complete: false, error: String(error?.message ?? error).slice(0, 4000) }, process.stderr);
  process.exitCode = 1;
});
