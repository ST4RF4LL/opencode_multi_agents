#!/usr/bin/env node
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { CONTROL_ACTIONS, WindowsControlSession, authorizeWindowsControl, controlError } from "./windows-control-core.mjs";
import { createWindowsNative, readControlSpec } from "./windows-control-native.mjs";

export function controlOptions(argv) {
  const args = { enabled: false };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--enable-winapp-control" && !args.enabled) args.enabled = true;
    else if (["--spec", "--plan"].includes(flag) && !args[flag.slice(2)] && argv[index + 1] && !argv[index + 1].startsWith("--")) args[flag.slice(2)] = argv[++index];
    else throw controlError("INVALID_ARGUMENTS");
  }
  return args;
}

export function validateControlPlan(plan, spec) {
  if (!plan || typeof plan !== "object" || Array.isArray(plan) || Object.keys(plan).some(key => key !== "steps")
    || !Array.isArray(plan.steps) || plan.steps.length === 0 || plan.steps.length > 50) throw controlError("INVALID_PLAN");
  for (const step of plan.steps) {
    if (!step || typeof step !== "object" || Array.isArray(step) || Object.keys(step).some(key => !["action", "control_id"].includes(key))
      || !CONTROL_ACTIONS.includes(step.action) || typeof step.control_id !== "string") throw controlError("INVALID_PLAN");
    const control = spec.controls.find(item => item.id === step.control_id);
    if (!control?.actions.includes(step.action) || control.id === spec.cleanup.invoke_control_id) throw controlError("PLAN_ACTION_NOT_ALLOWED");
  }
  return plan.steps;
}

export async function runControlProbe({ spec, plan, enabled = false, platform = process.platform, native = createWindowsNative() }) {
  const authorization = authorizeWindowsControl(spec, { enabled, platform });
  if (authorization.status === "SKIPPED") return authorization;
  // Validate the entire plan before acquiring a desktop or spawning any process.
  const steps = validateControlPlan(plan, authorization.spec);
  const session = new WindowsControlSession(authorization.spec, native, { enabled, platform });
  const opened = await session.open();
  if (opened.status !== "READY") return opened;
  const results = [];
  let failure = null;
  try {
    for (const step of steps) results.push({ action: step.action, ...await session.act(step.action, step.control_id) });
  } catch (error) { failure = error.controlCode ?? "CONTROL_FAILED"; }
  const closed = await session.close();
  return { ...closed, control_probe_status: failure || closed.cleanup.status === "FAILED" ? "FAILED" : "COMPLETED", failure, results };
}

export async function main(argv = process.argv.slice(2)) {
  const [command, ...rest] = argv;
  if (!command || ["help", "--help"].includes(command)) {
    process.stdout.write("用法：\n  windows-control-cli.mjs plan --spec <json> --plan <json>\n  windows-control-cli.mjs run --enable-winapp-control --spec <json> --plan <json>\n默认关闭；仅支持授权的 Windows 离线测试程序。只产出控制探针，不确认漏洞。\n");
    return;
  }
  if (!["plan", "run"].includes(command)) throw controlError("INVALID_ARGUMENTS");
  const options = controlOptions(rest);
  let result;
  if (command === "run" && !options.enabled) result = { status: "SKIPPED", reason: "WINDOWS_CONTROL_DISABLED" };
  else if (command === "run" && process.platform !== "win32") result = { status: "SKIPPED", reason: "WINDOWS_HOST_REQUIRED" };
  else {
    const spec = await readControlSpec(options.spec);
    const auth = authorizeWindowsControl(spec, { enabled: true, platform: command === "plan" ? "win32" : process.platform });
    if (auth.status !== "AUTHORIZED") result = auth;
    else {
      const plan = await readControlSpec(options.plan);
      const steps = validateControlPlan(plan, auth.spec);
      result = command === "plan"
        ? { status: "PLAN_VALID", structural_only: true, execution_authorized: false, binding_digest: auth.binding_digest, step_count: steps.length }
        : await runControlProbe({ spec, plan, enabled: options.enabled });
    }
  }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (["BLOCKED", "FAILED"].includes(result.status) || result.control_probe_status === "FAILED") process.exitCode = 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    process.stdout.write(`${JSON.stringify({ status: "BLOCKED", reason: error.controlCode ?? "CONTROL_FAILED" })}\n`);
    process.exitCode = 2;
  });
}
