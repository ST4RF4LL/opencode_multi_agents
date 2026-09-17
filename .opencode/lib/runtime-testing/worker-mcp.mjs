import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const endpoint = process.env.RUNTIME_WORKER_ENDPOINT;
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(endpoint ?? "") || !process.env.RUNTIME_WORKER_TOKEN) throw new Error("runtime-worker-lease-missing");
async function request(path, body = {}) {
  const response = await fetch(`${endpoint}${path}`, { method: "POST", headers: { Authorization: `Bearer ${process.env.RUNTIME_WORKER_TOKEN}`, "Content-Type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(50_000) });
  const result = await response.json(); if (!response.ok) throw new Error(result.error); return result;
}
const server = new Server({ name: "runtime-browser", version: "1.0.0" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [...await request("/tools"), {
  name: "submit_result", description: "提交当前工作包的中文结果，提交后该租约立即失效。SUPPORTED 只是待独立复核的支持证据。",
  inputSchema: { type: "object", properties: {
    execution_status: { enum: ["COMPLETED", "SKIPPED", "BLOCKED"] }, outcome: { enum: ["SUPPORTED", "COUNTEREVIDENCE", "NOT_OBSERVED", "INCONCLUSIVE"] },
    cleanup_status: { enum: ["NOT_REQUIRED", "SUCCEEDED", "FAILED", "UNKNOWN"] }, summary: { type: "string" },
    observations: { type: "array", items: { type: "string" } }, gaps: { type: "array", items: { type: "string" } },
    evidence_ids: { type: "array", items: { type: "string" } }, changes: { type: "array", items: { type: "object" } }, proof: { type: "object" },
  }, required: ["execution_status", "outcome", "cleanup_status", "summary", "observations", "gaps", "evidence_ids", "changes"] },
} ] }));
server.setRequestHandler(CallToolRequestSchema, async ({ params }) => {
  try { return { content: [{ type: "text", text: JSON.stringify(await request(params.name === "submit_result" ? "/submit" : "/call", params.name === "submit_result" ? params.arguments : params)) }] }; }
  catch (error) { return { isError: true, content: [{ type: "text", text: error.message }] }; }
});
await server.connect(new StdioServerTransport());
