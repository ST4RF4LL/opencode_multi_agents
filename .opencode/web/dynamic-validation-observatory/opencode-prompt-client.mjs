#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const emit = value => process.stdout.write(`${JSON.stringify(value)}\n`);

function requestTimeout() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  return { signal: controller.signal, clear: () => clearTimeout(timer) };
}

async function requestJson(url, options = {}) {
  const timeout = requestTimeout();
  try {
    const response = await fetch(url, { ...options, signal: timeout.signal, headers: { Accept: "application/json", ...(options.headers ?? {}) } });
    const text = await response.text();
    if (!response.ok) throw new Error(`HTTP ${response.status}${text.trim() ? `: ${text.trim().slice(0, 500)}` : ""}`);
    if (!text.trim()) return null;
    return JSON.parse(text);
  } finally {
    timeout.clear();
  }
}

function assistantForPrompt(messages, messageId) {
  if (!Array.isArray(messages)) return null;
  return [...messages].reverse().find(message => message?.info?.role === "assistant" && message.info.parentID === messageId) ?? null;
}

function assistantCompleted(assistant, statusType) {
  if (!assistant?.info || statusType !== "idle") return false;
  const finish = String(assistant.info.finish ?? "").trim().toLowerCase().replaceAll("_", "-");
  if (["tool-call", "tool-calls"].includes(finish)) return false;
  if (assistant.info.time?.completed !== undefined && assistant.info.time?.completed !== null) return true;
  return ["stop", "length", "content-filter", "cancelled", "canceled", "error"].includes(finish);
}

const requestPath = process.argv[2];
if (!requestPath || !isAbsolute(requestPath)) throw new Error("prompt client 需要绝对 request 路径。");
const spec = JSON.parse(await readFile(requestPath, "utf8"));
if (!/^http:\/\/(?:127\.0\.0\.1|localhost):\d+$/.test(spec.server_url ?? "")) throw new Error("OpenCode server 必须是 loopback HTTP 地址。");
if (typeof spec.session_id !== "string" || !spec.session_id || typeof spec.directory !== "string" || !isAbsolute(spec.directory)) throw new Error("OpenCode prompt request 的 session/directory 非法。");
if (!Array.isArray(spec.payload?.parts)) throw new Error("OpenCode prompt request 缺少 parts。");

const baseUrl = spec.server_url.replace(/\/$/, "");
const sessionPath = encodeURIComponent(spec.session_id);
const query = new URLSearchParams({ directory: spec.directory });
const messageId = `msg_owa_${randomUUID().replaceAll("-", "")}`;
let stopping = false;

async function abortSession() {
  try {
    await requestJson(`${baseUrl}/session/${sessionPath}/abort?${query}`, { method: "POST" });
  } catch (error) {
    emit({ type: "prompt_abort_warning", sessionID: spec.session_id, error: error.message });
  }
}

process.once("SIGTERM", () => {
  stopping = true;
  abortSession().finally(() => process.exit(143));
});
process.once("SIGINT", () => {
  stopping = true;
  abortSession().finally(() => process.exit(130));
});

try {
  const payload = { ...spec.payload, messageID: messageId };
  emit({ type: "prompt_request_started", sessionID: spec.session_id, messageID: messageId, agent: payload.agent ?? null });
  await requestJson(`${baseUrl}/session/${sessionPath}/prompt_async?${query}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  emit({ type: "prompt_status", sessionID: spec.session_id, messageID: messageId, state: "submitted" });

  const startedDeadline = Date.now() + Math.max(Number(process.env.OPENCODE_AGENT_START_TIMEOUT_MS) || 30_000, 1_000);
  const overallTimeout = Number(process.env.OPENCODE_PROMPT_TIMEOUT_MS) || 0;
  const overallDeadline = overallTimeout > 0 ? Date.now() + overallTimeout : null;
  let started = false;
  let idleSince = null;
  let lastState = "submitted";
  while (!stopping) {
    if (overallDeadline && Date.now() >= overallDeadline) throw new Error("OpenCode prompt 执行超时。");
    const [messages, statuses] = await Promise.all([
      requestJson(`${baseUrl}/session/${sessionPath}/message?${query}`),
      requestJson(`${baseUrl}/session/status?${query}`),
    ]);
    const assistant = assistantForPrompt(messages, messageId);
    const status = statuses && typeof statuses === "object" ? statuses[spec.session_id] : null;
    const statusType = typeof status?.type === "string" ? status.type : "idle";
    if (assistant?.info?.error) throw new Error(`OpenCode assistant 失败：${JSON.stringify(assistant.info.error).slice(0, 1000)}`);
    if (assistantCompleted(assistant, statusType)) {
      emit({ type: "prompt_status", sessionID: spec.session_id, messageID: messageId, state: "completed" });
      emit({ type: "prompt_response", sessionID: spec.session_id, messageID: messageId, finish: assistant.info.finish ?? null });
      process.exit(0);
    }
    const state = statusType === "retry" ? "retrying" : statusType === "busy" ? "running" : "idle";
    if (state !== lastState) {
      emit({ type: "prompt_status", sessionID: spec.session_id, messageID: messageId, state, status });
      lastState = state;
    }
    if (statusType === "busy" || statusType === "retry") {
      started = true;
      idleSince = null;
    } else if (statusType === "idle") {
      idleSince ??= Date.now();
    }
    if (!started && Date.now() >= startedDeadline) throw new Error("OpenCode 已接受 prompt，但 session 未进入运行状态。");
    if (started && idleSince && Date.now() - idleSince >= 5_000) throw new Error("OpenCode session 已空闲，但没有形成完整 assistant 响应。");
    await sleep(Math.max(Number(process.env.OPENCODE_POLL_INTERVAL_MS) || 500, 100));
  }
} catch (error) {
  emit({ type: "prompt_request_error", sessionID: spec.session_id, error: error.message });
  process.exit(1);
}
