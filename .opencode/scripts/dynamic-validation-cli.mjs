#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { platform } from "node:os";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { authorizeDynamicTask, chooseBrowserMode, sharedChromeReadiness } from "../web/dynamic-validation-observatory/dynamic-validation-core.mjs";
import { RequestHistoryStore } from "../web/dynamic-validation-observatory/request-history-store.mjs";
import { createAuditWorkbenchServer } from "../web/dynamic-validation-observatory/server.mjs";
import { DynamicValidationRunner } from "../web/dynamic-validation-observatory/validation-runner.mjs";
import { acceptanceTemplate, sealPlatformAcceptance, verifyAcceptanceMatrix } from "../web/dynamic-validation-observatory/platform-acceptance.mjs";

const OPENCODE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROJECT_ROOT = resolve(OPENCODE_ROOT, "..");
const DEFAULT_STATE_ROOT = resolve(PROJECT_ROOT, "reports", "platform", "dynamic-validation-standalone");
const TERMINAL = new Set(["completed", "failed", "cancelled"]);

function usage() {
  return `用法：
  node .opencode/scripts/dynamic-validation-cli.mjs doctor
  node .opencode/scripts/dynamic-validation-cli.mjs list [--state-root <dir>]
  node .opencode/scripts/dynamic-validation-cli.mjs run --spec <json> [--output <json>]
  node .opencode/scripts/dynamic-validation-cli.mjs serve [--host 127.0.0.1] [--port 4173] [--state-root <dir>]
  node .opencode/scripts/dynamic-validation-cli.mjs acceptance template --platform <windows|linux> --output <json>
  node .opencode/scripts/dynamic-validation-cli.mjs acceptance seal --input <json> --output <json>
  node .opencode/scripts/dynamic-validation-cli.mjs acceptance verify --windows <json> --linux <json> [--output <json>]
`;
}

function options(argv) {
  const value = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) value._.push(item);
    else {
      const key = item.slice(2).replaceAll("-", "_");
      const next = argv[index + 1];
      if (!next || next.startsWith("--")) value[key] = true;
      else { value[key] = next; index += 1; }
    }
  }
  return value;
}

async function jsonFile(path, label) {
  if (!path) throw new Error(`缺少 ${label}。`);
  return JSON.parse(await readFile(resolve(path), "utf8"));
}

function standaloneAuthorization(spec) {
  const input = spec.authorization ?? {};
  return {
    enabled: spec.enabled === true,
    explicit_authorization: input.explicit_authorization === true,
    test_environment: input.test_environment === true,
    target_base_url: input.target_base_url,
    browser_mode: input.browser_mode ?? "auto",
    accounts: {
      attacker: input.attacker_account,
      victim: input.victim_account,
    },
  };
}

async function output(value, path = null) {
  const text = `${JSON.stringify(value, null, 2)}\n`;
  if (path) await writeFile(resolve(path), text, { encoding: "utf8", mode: 0o600 });
  else process.stdout.write(text);
}

async function runStandalone(spec, outputPath) {
  const authorization = authorizeDynamicTask(standaloneAuthorization(spec), { requireAccounts: true });
  if (!authorization.authorized) {
    await output({ schema_version: 1, status: "SKIPPED", issues: authorization.issues, recorded_at: new Date().toISOString() }, outputPath);
    return;
  }
  const requiredPaths = ["state_root", "reports_root", "runtime_root", "registry_path", "roles_path"];
  for (const field of requiredPaths) {
    if (!spec[field] || !isAbsolute(spec[field])) throw new Error(`${field} 必须是绝对路径。`);
  }
  const repository = spec.repository ?? {};
  if (!repository.path || !repository.config_path || !isAbsolute(repository.path) || !isAbsolute(repository.config_path)) throw new Error("repository.path 与 repository.config_path 必须是绝对路径。");
  const runner = new DynamicValidationRunner({
    stateRoot: spec.state_root,
    enabled: true,
    command: spec.opencode_command ?? "opencode",
    registryPath: spec.registry_path,
    rolesPath: spec.roles_path,
  });
  const input = {
    ...spec.authorization,
    browser_mode: spec.authorization.browser_mode ?? "auto",
  };
  const executionPaths = spec.execution_paths ?? {};
  for (const field of ["workspace_root", "source_root", "reports_root", "tmp_root"]) {
    if (!executionPaths[field] || !isAbsolute(executionPaths[field])) throw new Error(`execution_paths.${field} 必须是绝对路径。`);
  }
  let run = await runner.create({
    input,
    repository,
    reportsRoot: spec.reports_root,
    runtimeRoot: spec.runtime_root,
    executionPaths,
    requestDescriptor: spec.request_descriptor,
    idempotencyKey: spec.idempotency_key ?? randomUUID(),
  });
  while (!TERMINAL.has(run.status)) {
    await new Promise(resolveWait => setTimeout(resolveWait, 250));
    run = runner.getRun(run.id);
  }
  await output({ schema_version: 1, status: run.status.toUpperCase(), run }, outputPath);
}

export async function main(argv = process.argv.slice(2)) {
  const [command, ...rest] = argv;
  const args = options(rest);
  const stateRoot = resolve(args.state_root || DEFAULT_STATE_ROOT);
  if (!command || command === "help" || command === "--help") {
    process.stdout.write(usage());
    return;
  }
  if (command === "doctor") {
    const desktopAvailable = process.env.DYNAMIC_VALIDATION_DESKTOP !== "0";
    await output({
      schema_version: 1,
      status: "READY",
      platform: { os: platform(), desktop_available: desktopAvailable },
      deployment: { mode: "native_process", container_runtime: "DISABLED", supported_hosts: ["windows", "linux"] },
      browser_default: chooseBrowserMode({ platform: platform(), desktopAvailable }),
      shared_chrome: {
        status: "USER_SETUP_REQUIRED",
        minimum_major_version: 144,
        remote_debugging_required: true,
        profile_connection_confirmation_required: true,
        warning: sharedChromeReadiness().warning,
      },
      chrome_devtools_package: process.env.CHROME_DEVTOOLS_MCP_PACKAGE ?? "chrome-devtools-mcp@1.8.0",
      safety_scope: ["localhost", "127.0.0.1", "[::1]"],
    });
    return;
  }
  if (command === "list") {
    const history = new RequestHistoryStore({ stateRoot });
    const items = await history.list({ limit: args.limit ?? 100 });
    await output({ items, count: items.length }, args.output);
    return;
  }
  if (command === "run") {
    await runStandalone(await jsonFile(args.spec, "--spec"), args.output);
    return;
  }
  if (command === "acceptance") {
    const [action] = args._;
    if (action === "template") {
      if (!args.output) throw new Error("验收模板必须使用 --output 写入明确路径。");
      await output(acceptanceTemplate(String(args.platform ?? "")), args.output);
      return;
    }
    if (action === "seal") {
      if (!args.output) throw new Error("封存验收证据必须使用 --output 写入明确路径。");
      await output(sealPlatformAcceptance(await jsonFile(args.input, "--input")), args.output);
      return;
    }
    if (action === "verify") {
      const result = verifyAcceptanceMatrix(await jsonFile(args.windows, "--windows"), await jsonFile(args.linux, "--linux"));
      await output(result, args.output);
      if (result.status !== "PASS") process.exitCode = 2;
      return;
    }
    throw new Error(`未知 acceptance 子命令：${action ?? ""}\n${usage()}`);
  }
  if (command === "serve") {
    const host = String(args.host ?? "127.0.0.1");
    if (!new Set(["localhost", "127.0.0.1", "::1", "[::1]"]).has(host)) throw new Error("独立动态服务只允许监听 loopback 地址。");
    const port = Number(args.port ?? 4173);
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("端口无效。");
    const server = createAuditWorkbenchServer({ stateRoot, repositories: [], requestStateRoot: resolve(stateRoot, "requests") });
    server.listen(port, host, () => process.stdout.write(`动态验证组件已启动：http://${host}:${server.address().port}\n`));
    return;
  }
  throw new Error(`未知命令：${command}\n${usage()}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
