#!/usr/bin/env node

import { resolve } from "node:path";
import { probeEngines, runSemgrepScan, sha256 } from "./semgrep-core.mjs";

const MAX_OUTPUT_BYTES = 16 * 1024;
const MAX_ERROR_BYTES = 4 * 1024;

function usage() {
  return `Usage:
  node .opencode/scripts/semgrep-scan.mjs health
  node .opencode/scripts/semgrep-scan.mjs scan \\
    --audit-id ID --session-id ID --agent-name NAME \\
    --target PATH --rule PATH [--rule PATH ...] [options]

Options:
  --engine auto|opengrep|semgrep  Scanner selection (default: auto)
  --sarif PATH                    Output below reports/sarif/
  --jobs N                        Parallel jobs, 1-32 (default: 2)
  --rule-timeout-seconds N        Per-rule timeout, 1-600 (default: 30)
  --process-timeout-ms N          Process timeout, 1000-900000 (default: 300000)
  --max-memory-mb N               Engine memory limit, 0-131072 (default: 0)
  --exclude PATTERN               Repeatable exclude, at most 100
  -h, --help                      Show this help

Environment:
  OPENGREP_BIN, SEMGREP_BIN, SEMGREP_ENGINE
`;
}

function truncateUtf8(value, maxBytes) {
  const buffer = Buffer.from(String(value ?? ""), "utf8");
  if (buffer.length <= maxBytes) return buffer.toString("utf8");
  return `${buffer.subarray(0, Math.max(0, maxBytes - 32)).toString("utf8")}\n...[truncated ${buffer.length - maxBytes} bytes]`;
}

function emitJson(value, stream = process.stdout) {
  const line = `${JSON.stringify(value)}\n`;
  const bytes = Buffer.byteLength(line);
  if (bytes > MAX_OUTPUT_BYTES) {
    const fallback = {
      complete: false,
      error: "CLI summary exceeded its safety limit; full artifacts remain on disk",
      summary_bytes: bytes,
      summary_sha256: sha256(line),
    };
    stream.write(`${JSON.stringify(fallback)}\n`);
    return false;
  }
  stream.write(line);
  return true;
}

function takeValue(args, index, option) {
  const value = args[index + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${option} requires a value`);
  return value;
}

function boundedInteger(value, option, minimum, maximum) {
  if (!/^\d+$/.test(value)) throw new Error(`${option} must be an integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${option} must be between ${minimum} and ${maximum}`);
  }
  return parsed;
}

function parseScanArgs(args) {
  const options = {
    engine: "auto",
    jobs: 2,
    ruleTimeoutSeconds: 30,
    processTimeoutMs: 300_000,
    maxMemoryMb: 0,
    rulePaths: [],
    excludes: [],
  };
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (["-h", "--help"].includes(option)) return { help: true };
    const value = takeValue(args, index, option);
    index += 1;
    switch (option) {
      case "--audit-id": options.auditId = value; break;
      case "--session-id": options.sessionId = value; break;
      case "--agent-name": options.agentName = value; break;
      case "--target": options.targetPath = value; break;
      case "--rule": options.rulePaths.push(value); break;
      case "--engine":
        if (!["auto", "opengrep", "semgrep"].includes(value)) throw new Error("--engine must be auto, opengrep, or semgrep");
        options.engine = value;
        break;
      case "--sarif": options.sarifPath = value; break;
      case "--jobs": options.jobs = boundedInteger(value, option, 1, 32); break;
      case "--rule-timeout-seconds": options.ruleTimeoutSeconds = boundedInteger(value, option, 1, 600); break;
      case "--process-timeout-ms": options.processTimeoutMs = boundedInteger(value, option, 1_000, 900_000); break;
      case "--max-memory-mb": options.maxMemoryMb = boundedInteger(value, option, 0, 131_072); break;
      case "--exclude": options.excludes.push(value); break;
      default: throw new Error(`Unknown option: ${option}`);
    }
  }
  for (const [name, value] of [
    ["--audit-id", options.auditId],
    ["--session-id", options.sessionId],
    ["--agent-name", options.agentName],
    ["--target", options.targetPath],
  ]) {
    if (!value) throw new Error(`${name} is required`);
  }
  if (options.rulePaths.length === 0) throw new Error("At least one --rule is required");
  if (options.rulePaths.length > 64) throw new Error("At most 64 --rule options are allowed");
  if (options.excludes.length > 100) throw new Error("At most 100 --exclude options are allowed");
  for (const value of [...options.rulePaths, ...options.excludes, options.targetPath, options.sarifPath ?? ""]) {
    if (Buffer.byteLength(value, "utf8") > 4_096 || value.includes("\0")) throw new Error("Path or pattern argument is invalid or too long");
  }
  return options;
}

async function health(workspaceRoot) {
  const engines = await probeEngines({ workspaceRoot });
  const publicEngines = engines.map(({ command: _command, ...engine }) => engine);
  return {
    complete: true,
    transport: "direct-cli",
    healthy: engines.some(engine => engine.available),
    workspace: ".",
    auto_selected: engines.find(engine => engine.available)?.engine ?? null,
    engines: publicEngines,
  };
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (!command || ["-h", "--help"].includes(command)) {
    process.stdout.write(usage());
    return;
  }
  const workspaceRoot = resolve(process.cwd());
  if (command === "health") {
    if (args.length > 0) throw new Error("health does not accept arguments");
    const result = await health(workspaceRoot);
    if (!emitJson(result)) process.exitCode = 1;
    else if (!result.healthy) process.exitCode = 1;
    return;
  }
  if (command !== "scan") throw new Error(`Unknown command: ${command}`);
  const options = parseScanArgs(args);
  if (options.help) {
    process.stdout.write(usage());
    return;
  }
  const result = await runSemgrepScan({ workspaceRoot, ...options });
  const rulePaths = result.rule_paths.slice(0, 16);
  const summary = {
    complete: true,
    transport: "direct-cli",
    ...result,
    rule_path_count: result.rule_paths.length,
    rule_paths: rulePaths,
    rule_paths_truncated: result.rule_paths.length > rulePaths.length,
  };
  if (!emitJson(summary)) process.exitCode = 1;
}

main().catch(error => {
  emitJson({
    complete: false,
    error: truncateUtf8(error?.message ?? error, MAX_ERROR_BYTES),
  }, process.stderr);
  process.exitCode = 1;
});
