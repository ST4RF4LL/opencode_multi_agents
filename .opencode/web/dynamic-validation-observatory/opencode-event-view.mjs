const MAX_EVENT_TEXT = 32 * 1024;

function text(value) {
  if (value === undefined || value === null) return "";
  const serialized = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  const output = serialized === undefined ? String(value) : serialized;
  return output.length > MAX_EVENT_TEXT ? `${output.slice(0, MAX_EVENT_TEXT)}\n…（事件内容已截断）` : output;
}

function compactTokens(tokens) {
  if (!tokens || typeof tokens !== "object") return "";
  const fields = [
    ["total", "总计"], ["input", "输入"], ["output", "输出"], ["reasoning", "推理"],
  ].flatMap(([key, label]) => Number.isFinite(tokens[key]) ? [`${label} ${tokens[key]}`] : []);
  if (Number.isFinite(tokens.cache?.read)) fields.push(`缓存读取 ${tokens.cache.read}`);
  if (Number.isFinite(tokens.cache?.write)) fields.push(`缓存写入 ${tokens.cache.write}`);
  return fields.join(" · ");
}

function toolOutput(state) {
  const value = state.output ?? state.error;
  if (typeof value !== "string") return text(value);
  try {
    const parsed = JSON.parse(value);
    if (parsed && typeof parsed === "object" && typeof parsed.output === "string") return text(parsed.output);
  } catch {}
  return text(value);
}

function rawView(entry, message, label = "Runner 输出") {
  return { ...entry, kind: entry.source === "stderr" ? "error" : "raw", label, status: null, body: text(message), detail: "" };
}

export function openCodeEventView(entry) {
  const base = { occurred_at: entry?.occurred_at ?? null, source: entry?.source ?? "stdout" };
  const message = String(entry?.message ?? "");
  let event;
  try { event = JSON.parse(message); } catch { return rawView(base, message); }
  if (!event || typeof event !== "object") return rawView(base, message);

  const part = event.part && typeof event.part === "object" ? event.part : {};
  const sessionId = event.sessionID ?? event.session_id ?? part.sessionID ?? null;
  const common = { ...base, session_id: sessionId, event_type: event.type ?? null };
  if (event.type === "text") {
    return { ...common, kind: "text", label: "Agent", status: null, body: text(part.text ?? event.text), detail: "" };
  }
  if (event.type === "reasoning") {
    return { ...common, kind: "reasoning", label: "推理", status: null, body: text(part.text ?? event.text), detail: "" };
  }
  if (event.type === "tool_use") {
    const state = part.state && typeof part.state === "object" ? part.state : {};
    const tool = part.tool ?? "tool";
    return {
      ...common,
      kind: "tool",
      label: text(state.metadata?.title) || tool,
      tool,
      call_id: part.callID ?? null,
      status: state.status ?? "unknown",
      body: toolOutput(state),
      detail: text(state.input),
    };
  }
  if (event.type === "step_start") {
    return { ...common, kind: "step", label: "开始新一轮", status: "running", body: "", detail: "" };
  }
  if (event.type === "step_finish") {
    const tokenText = compactTokens(part.tokens);
    const costText = Number.isFinite(part.cost) ? `费用 $${part.cost.toFixed(6)}` : "";
    return {
      ...common,
      kind: "step",
      label: "本轮完成",
      status: "completed",
      body: [part.reason ? `原因 ${part.reason}` : "", tokenText, costText].filter(Boolean).join(" · "),
      detail: "",
    };
  }
  if (event.type === "prompt_request_started") {
    return { ...common, kind: "status", label: "请求已提交", status: "running", body: text(event.message), detail: "" };
  }
  if (event.type === "prompt_status") {
    const status = event.status ?? event.state ?? "unknown";
    return { ...common, kind: "status", label: "OpenCode 状态", status, body: text(event.message ?? status), detail: "" };
  }
  if (event.type === "prompt_request_error" || event.type === "error") {
    return { ...common, kind: "error", label: "OpenCode 错误", status: "error", body: text(event.error?.message ?? event.message ?? event.error), detail: "" };
  }
  return rawView(common, message, event.type ? `OpenCode · ${event.type}` : "Runner 输出");
}
