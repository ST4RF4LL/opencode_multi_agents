#!/usr/bin/env node
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { CONTROL_ACTIONS, WindowsControlSession, controlError } from "./windows-control-core.mjs";
import { controlOptions } from "./windows-control-cli.mjs";
import { createWindowsNative, readControlSpec } from "./windows-control-native.mjs";

const DESCRIPTIONS = {
  status: "读取本会话状态；不会启动目标程序。",
  inspect: "观察已登记控件，仅返回存在和启用状态。",
  set_value: "向已登记测试输入框写入本次无害 marker，不接受任意文本或凭证。",
  invoke: "调用已登记控件的直接 InvokePattern。",
  get_state: "检查已登记控件是否包含本次 marker，不返回原始内容。",
  wait_for: "有界等待已登记控件出现本次 marker。",
  cleanup: "执行已登记应用内清理并验证 marker 消失。",
  close: "清理本次 marker 并释放桌面租约；不结束目标应用进程。",
};

export function controlTools() {
  return Object.entries(DESCRIPTIONS).map(([name, description]) => ({ name, description,
    inputSchema: { type: "object", properties: CONTROL_ACTIONS.includes(name) ? { control_id: { type: "string", maxLength: 80 } } : {},
      required: CONTROL_ACTIONS.includes(name) ? ["control_id"] : [], additionalProperties: false },
    annotations: { readOnlyHint: ["status", "inspect", "get_state", "wait_for"].includes(name), openWorldHint: false },
  }));
}

export function createControlMcp(session) {
  const server = new Server({ name: "windows-control", version: "0.1.0" }, { capabilities: { tools: {} } });
  let accepting = true;
  let active = null;
  let opened = false;
  const result = (value, isError = false) => ({ content: [{ type: "text", text: JSON.stringify(value) }], isError });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: controlTools() }));
  server.setRequestHandler(CallToolRequestSchema, async request => {
    const { name, arguments: args = {} } = request.params;
    if (!accepting) return result({ status: "BLOCKED", reason: "SESSION_CLOSED" }, true);
    if (active) return result({ status: "BLOCKED", reason: "SESSION_BUSY" }, true);
    if (!Object.hasOwn(DESCRIPTIONS, name) || !args || typeof args !== "object" || Array.isArray(args)
      || Object.keys(args).some(key => !CONTROL_ACTIONS.includes(name) || key !== "control_id")
      || (CONTROL_ACTIONS.includes(name) && typeof args.control_id !== "string")) return result({ status: "BLOCKED", reason: "INVALID_ARGUMENTS" }, true);
    const work = async () => {
      try {
        if (name === "status") return result(session.status());
        if (name === "close") { accepting = false; return result(await session.close()); }
        if (session.status().status === "SKIPPED") return result(session.status());
        if (CONTROL_ACTIONS.includes(name)) session.validateAction(name, args.control_id);
        if (!opened) { opened = true; await session.open(); }
        if (session.status().status === "SKIPPED") return result(session.status());
        if (name === "cleanup") return result(await session.cleanup());
        return result(await session.act(name, args.control_id));
      } catch (error) { return result({ status: "BLOCKED", reason: error.controlCode ?? "CONTROL_FAILED" }, true); }
    };
    active = work();
    try { return await active; } finally { active = null; }
  });
  const shutdown = async () => {
    accepting = false;
    if (active) await active;
    return session.close();
  };
  server.onclose = () => { shutdown().catch(() => {}); };
  return { server, shutdown };
}

export async function main(argv = process.argv.slice(2)) {
  const options = controlOptions(argv);
  if (options.plan) throw controlError("INVALID_ARGUMENTS");
  // Disabled startup and tools/list have no target or native-process side effects.
  const spec = options.enabled && process.platform === "win32" ? await readControlSpec(options.spec) : null;
  const session = new WindowsControlSession(spec, createWindowsNative(), { enabled: options.enabled });
  const { server } = createControlMcp(session);
  await server.connect(new StdioServerTransport());
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(() => { process.stderr.write("Windows 控制 MCP 无法启动；未输出敏感错误内容。\n"); process.exitCode = 2; });
}
