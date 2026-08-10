const state = {
  runs: [],
  selectedRunId: null,
  run: null,
  selectedExchange: 0,
  exchangeSide: "request",
};

const elements = Object.fromEntries([
  "run-count", "run-list", "page-title", "page-subtitle", "run-status", "loading", "error", "empty", "run-detail",
  "environment-facts", "finding-title", "finding-level", "finding-summary", "verdict", "observation-count", "observation-list",
  "network-summary", "network-warning", "network-empty", "network-workspace", "exchange-list", "exchange-method", "exchange-url",
  "exchange-timing", "request-tab", "response-tab", "exchange-content",
].map(id => [id, document.getElementById(id)]));

function node(tag, className, text) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined && text !== null) item.textContent = String(text);
  return item;
}

function show(name) { elements[name].hidden = false; }
function hide(name) { elements[name].hidden = true; }

function formatDate(value) {
  if (!value) return "时间未知";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? String(value) : new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "medium" }).format(date);
}

function short(value, size = 12) {
  if (!value) return "—";
  const text = String(value);
  return text.length > size ? `${text.slice(0, size)}…` : text;
}

function urlPath(value) {
  try {
    return new URL(value).pathname;
  } catch {
    return value || "URL 未记录";
  }
}

function showError(error) {
  hide("loading"); hide("run-detail");
  elements.error.textContent = error.message;
  show("error");
  setStatus("读取失败", "error");
}

function setStatus(text, kind = "neutral") {
  elements["run-status"].textContent = text;
  elements["run-status"].className = `status status-${kind}`;
}

function renderRunList() {
  elements["run-count"].textContent = state.runs.length;
  elements["run-list"].replaceChildren();
  state.runs.forEach(run => {
    const button = node("button", "run-item");
    button.type = "button";
    button.setAttribute("aria-current", String(run.id === state.selectedRunId));
    const row = node("span", "run-item-row");
    row.append(node("strong", "", run.finding_id), node("span", "run-state", run.verification_level ?? run.outcome));
    button.append(row, node("small", "", `${run.agent_name} · ${formatDate(run.recorded_at)}`));
    button.addEventListener("click", () => selectRun(run.id).catch(showError));
    elements["run-list"].append(button);
  });
}

function renderFacts(run) {
  const environment = run.environment;
  const facts = [
    ["授权目标", environment.base_url],
    ["允许 Origin", (environment.allowed_origins ?? []).join(", ")],
    ["Subagent", run.actor.agent_name],
    ["Agent session", run.actor.agent_session_id],
    ["浏览器后端", environment.browser_backend ? `${environment.browser_backend.name} · ${environment.browser_backend.resolved_version}` : null],
    ["隔离上下文", `${environment.attacker_context_id ?? "—"} / ${environment.victim_context_id ?? "—"}`],
    ["代码版本", `${environment.source_repository ?? "—"} @ ${short(environment.source_commit)}`],
    ["环境绑定摘要", short(environment.binding_digest, 18)],
  ];
  elements["environment-facts"].replaceChildren();
  facts.forEach(([label, value]) => {
    const wrapper = node("div");
    wrapper.append(node("dt", "", label), node("dd", "", value ?? "—"));
    elements["environment-facts"].append(wrapper);
  });
}

function renderFinding(run) {
  const finding = run.finding;
  elements["finding-title"].textContent = `${finding.id} · ${finding.vulnerability_type_id ?? "未分类"}`;
  elements["finding-level"].textContent = finding.verification_level ?? finding.outcome;
  elements["finding-summary"].textContent = finding.summary ?? "没有保存 Bug 摘要。";
  const cleanup = finding.cleanup?.status ?? "UNKNOWN";
  const gaps = (finding.residual_gaps ?? []).length;
  elements.verdict.textContent = `判定：${finding.outcome}；验证等级：${finding.verification_level ?? "—"}；清理：${cleanup}；残留缺口：${gaps}。`;
}

function renderObservations(run) {
  const observations = run.observations ?? [];
  elements["observation-count"].textContent = `${observations.length} 个观察`;
  elements["observation-list"].replaceChildren();
  observations.forEach((observation, index) => {
    const item = node("li", "observation-item");
    const content = node("div");
    content.append(node("strong", "", `${observation.observation_id} · ${observation.outcome}`), node("p", "", observation.claim));
    const evidenceData = (observation.evidence ?? []).find(evidence => evidence.data)?.data;
    if (evidenceData) content.append(node("div", "evidence-data", JSON.stringify(evidenceData, null, 2)));
    item.append(node("span", "observation-index", index + 1), content);
    elements["observation-list"].append(item);
  });
}

function formatHeaders(headers) {
  return (headers ?? []).map(header => `${header.name}: ${header.value}`).join("\n");
}

function formatBody(body) {
  if (!body) return "";
  if (typeof body === "string") return body;
  if (typeof body.text === "string") return body.text;
  return JSON.stringify(body, null, 2);
}

function exchangeText(exchange, side) {
  if (side === "request") {
    const request = exchange.request;
    const headers = formatHeaders(request.headers);
    const body = formatBody(request.body);
    return `${request.method} ${request.url}\n${headers}${headers && body ? "\n\n" : ""}${body}`.trim();
  }
  const response = exchange.response;
  const status = response.status === null ? "NO RESPONSE" : `HTTP ${response.status} ${response.status_text ?? ""}`.trim();
  const headers = formatHeaders(response.headers);
  const body = formatBody(response.body);
  const error = response.error ? `\n\nError: ${response.error}` : "";
  return `${status}\n${headers}${headers && body ? "\n\n" : ""}${body}${error}`.trim();
}

function renderSelectedExchange() {
  const exchanges = state.run?.network?.exchanges ?? [];
  const exchange = exchanges[state.selectedExchange];
  if (!exchange) return;
  elements["exchange-method"].textContent = exchange.request.method;
  elements["exchange-url"].textContent = exchange.request.url;
  elements["exchange-timing"].textContent = `${exchange.response.status ?? "ERR"} · ${exchange.duration_ms ?? "—"} ms · ${exchange.browser_context_id ?? "context 未记录"}`;
  elements["request-tab"].setAttribute("aria-selected", String(state.exchangeSide === "request"));
  elements["response-tab"].setAttribute("aria-selected", String(state.exchangeSide === "response"));
  elements["exchange-content"].textContent = exchangeText(exchange, state.exchangeSide);
  [...elements["exchange-list"].children].forEach((button, index) => button.setAttribute("aria-current", String(index === state.selectedExchange)));
}

function renderNetwork(run) {
  const network = run.network;
  elements["network-summary"].textContent = `${network.exchange_count} 个 exchange · ${network.completeness}`;
  elements["network-warning"].hidden = !network.warning;
  elements["network-warning"].textContent = network.warning ?? "";
  const exchanges = network.exchanges ?? [];
  elements["network-empty"].hidden = exchanges.length > 0;
  elements["network-workspace"].hidden = exchanges.length === 0;
  elements["exchange-list"].replaceChildren();
  exchanges.forEach((exchange, index) => {
    const button = node("button", "exchange-item");
    button.type = "button";
    const labels = node("span");
    labels.append(node("strong", "", `${exchange.request.method} ${urlPath(exchange.request.url)}`), node("small", "", `${exchange.phase} · ${exchange.response.status ?? "ERR"}`));
    button.append(node("span", "exchange-sequence", exchange.sequence ?? index + 1), labels);
    button.addEventListener("click", () => { state.selectedExchange = index; renderSelectedExchange(); });
    elements["exchange-list"].append(button);
  });
  state.selectedExchange = 0;
  state.exchangeSide = "request";
  renderSelectedExchange();
}

function renderRun(run) {
  state.run = run;
  elements["page-title"].textContent = `${run.audit_id} / ${run.finding.id}`;
  elements["page-subtitle"].textContent = `${run.actor.agent_name} · ${formatDate(run.recorded_at)}`;
  setStatus(run.finding.outcome, run.finding.outcome === "SUPPORTED_RUNTIME" ? "success" : "error");
  renderFacts(run);
  renderFinding(run);
  renderObservations(run);
  renderNetwork(run);
  hide("loading"); hide("error"); hide("empty"); show("run-detail");
}

async function selectRun(id) {
  state.selectedRunId = id;
  renderRunList();
  setStatus("读取中");
  const response = await fetch(`/api/runs/${encodeURIComponent(id)}`, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`读取运行失败：HTTP ${response.status}`);
  renderRun((await response.json()).run);
}

async function init() {
  try {
    const response = await fetch("/api/runs", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`读取运行列表失败：HTTP ${response.status}`);
    state.runs = (await response.json()).runs;
    renderRunList();
    hide("loading");
    if (state.runs.length === 0) { show("empty"); return; }
    await selectRun(state.runs[0].id);
  } catch (error) {
    showError(error);
  }
}

elements["request-tab"].addEventListener("click", () => { state.exchangeSide = "request"; renderSelectedExchange(); });
elements["response-tab"].addEventListener("click", () => { state.exchangeSide = "response"; renderSelectedExchange(); });

init();
