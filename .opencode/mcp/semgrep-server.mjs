#!/usr/bin/env node

import { McpServer } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js";
import { StdioServerTransport } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js";
import { z } from "../node_modules/zod/index.js";
import { resolve } from "node:path";
import { probeEngines, runSemgrepScan } from "./semgrep-core.mjs";

const WORKSPACE_ROOT = resolve(process.cwd());
let scanQueue = Promise.resolve();

function textResult(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

function serialized(operation) {
  const queued = scanQueue.then(operation, operation);
  scanQueue = queued.then(() => undefined, () => undefined);
  return queued;
}

const server = new McpServer({
  name: "semgrep",
  version: "1.0.0",
}, {
  capabilities: { tools: {} },
});

server.registerTool("semgrep_health", {
  description: "Report local OpenGrep and Semgrep availability. Auto mode prefers OpenGrep and falls back to Semgrep unless SEMGREP_ENGINE overrides the order.",
}, async () => {
  const engines = await probeEngines({ workspaceRoot: WORKSPACE_ROOT });
  const publicEngines = engines.map(({ command: _command, ...engine }) => engine);
  return textResult({
    healthy: engines.some(engine => engine.available),
    workspace: ".",
    auto_selected: engines.find(engine => engine.available)?.engine ?? null,
    engines: publicEngines,
  });
});

server.registerTool("semgrep_scan", {
  description: "Run local Semgrep-compatible YAML rules with OpenGrep or Semgrep against a workspace target. Remote registry configs and arbitrary CLI arguments are forbidden. Raw JSON is retained under tmp/<audit_id>/semgrep and a normalized SARIF run is created or appended under reports/sarif.",
  inputSchema: {
    audit_id: z.string(),
    session_id: z.string(),
    agent_name: z.string(),
    target_path: z.string(),
    rule_paths: z.array(z.string()).min(1),
    engine: z.enum(["auto", "opengrep", "semgrep"]).optional(),
    sarif_path: z.string().optional(),
    jobs: z.number().int().min(1).max(32).optional(),
    rule_timeout_seconds: z.number().int().min(1).max(600).optional(),
    process_timeout_ms: z.number().int().min(1_000).max(900_000).optional(),
    max_memory_mb: z.number().int().min(0).max(131_072).optional(),
    excludes: z.array(z.string()).max(100).optional(),
  },
}, async input => textResult(await serialized(() => runSemgrepScan({
  workspaceRoot: WORKSPACE_ROOT,
  auditId: input.audit_id,
  sessionId: input.session_id,
  agentName: input.agent_name,
  targetPath: input.target_path,
  rulePaths: input.rule_paths,
  engine: input.engine ?? "auto",
  sarifPath: input.sarif_path,
  jobs: input.jobs ?? 2,
  ruleTimeoutSeconds: input.rule_timeout_seconds ?? 30,
  processTimeoutMs: input.process_timeout_ms ?? 300_000,
  maxMemoryMb: input.max_memory_mb ?? 0,
  excludes: input.excludes ?? [],
}))));

const transport = new StdioServerTransport();
await server.connect(transport);
