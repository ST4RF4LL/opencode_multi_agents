const state = {
  workspace: { summary: {}, audits: [], findings: [], reports: [], artifacts: [] },
  repositories: [],
  validationRuns: [],
  validationRequests: [],
  runtime: null,
  selectedAuditId: null,
  selectedValidationId: null,
  view: "dashboard",
  eventSource: null,
  liveRefresh: null,
  validationEventSource: null,
  validationLiveRefresh: null,
};

const VIEW_META = {
  dashboard: ["源码审计工作台", "安全态势 / 概览"],
  projects: ["审计项目", "资产管理 / 服务端白名单"],
  audits: ["审计任务", "任务中心 / 端到端运行"],
  findings: ["漏洞发现", "风险中心 / canonical findings"],
  reports: ["审计报告", "交付中心 / 封存报告"],
  validation: ["动态验证", "验证中心 / localhost 证据"],
  runtime: ["Agent 运行时", "平台管理 / OpenCode runner"],
};

const $ = id => document.getElementById(id);

function element(tag, className, text) {
  const value = document.createElement(tag);
  if (className) value.className = className;
  if (text !== undefined && text !== null) value.textContent = String(text);
  return value;
}

function cell(row, text, className = "") {
  row.append(element("td", className, text));
}

function table(headers) {
  const value = element("table", "table");
  const head = element("thead");
  const row = element("tr");
  headers.forEach(label => row.append(element("th", "", label)));
  head.append(row);
  const body = element("tbody");
  value.append(head, body);
  return [value, body];
}

function status(value) {
  const labels = {
    queued: "等待运行", preparing: "准备中", running: "运行中", pausing: "正在暂停", paused: "已暂停", cancelling: "正在取消",
    cancelled: "已取消", completed: "已完成", failed: "失败", artifact_only: "历史制品", unvalidated: "未验证",
    supported_runtime: "运行时已证实", not_confirmed: "未证实", stored_cross_user: "跨用户存储型 XSS", stored_same_user: "同用户存储型 XSS",
  };
  const key = String(value ?? "unknown").toLowerCase();
  return element("span", `status ${key}`, labels[key] ?? value ?? "未知");
}

function formatDate(value) {
  if (!value) return "时间未知";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? String(value) : new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function short(value, length = 12) {
  if (!value) return "—";
  const text = String(value);
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

function bytes(value) {
  if (!Number.isFinite(value)) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function toast(message) {
  const value = $("toast");
  value.textContent = message;
  value.classList.add("show");
  window.setTimeout(() => value.classList.remove("show"), 2600);
}

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { Accept: "application/json", ...(options.headers ?? {}) }, ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.message ?? `请求失败：HTTP ${response.status}`);
  return body;
}

function setView(view) {
  state.view = view;
  document.querySelectorAll(".view").forEach(item => item.classList.toggle("active", item.id === `view-${view}`));
  document.querySelectorAll(".nav button[data-view]").forEach(item => item.classList.toggle("active", item.dataset.view === view));
  $("page-title").textContent = VIEW_META[view][0];
  $("breadcrumb").textContent = VIEW_META[view][1];
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function metric(label, value, note) {
  const item = element("article", "metric");
  item.append(element("span", "", label), element("strong", "", value), element("small", "", note));
  return item;
}

function renderMetrics() {
  const summary = state.workspace.summary;
  const grid = $("metric-grid");
  grid.replaceChildren(
    metric("审计任务", summary.audit_count ?? 0, `${summary.active_audits ?? 0} 个运行中`),
    metric("canonical 漏洞", summary.finding_count ?? 0, `${summary.severity?.critical ?? 0} 个严重`),
    metric("封存报告", summary.report_count ?? 0, "Markdown 交付件"),
    metric("动态验证", summary.validation_run_count ?? 0, "显式授权的 localhost 运行"),
    metric("白名单仓库", state.repositories.length, `${state.repositories.filter(repo => repo.configured).length} 个配置就绪`),
  );
  $("active-audit-badge").textContent = summary.active_audits ?? 0;
  $("finding-badge").textContent = summary.finding_count ?? 0;
}

function auditListItem(audit) {
  const button = element("button", "audit-item");
  button.type = "button";
  const identity = element("span");
  identity.append(element("strong", "", audit.name), element("small", "mono", `${audit.id} · ${audit.repository_name ?? "仓库未知"}`));
  const progress = element("span");
  const bar = element("span", "progress");
  const fill = element("i");
  fill.style.width = `${audit.progress ?? 0}%`;
  bar.append(fill);
  progress.append(element("small", "", `${audit.stage} · ${audit.progress ?? 0}%`), bar);
  button.append(identity, progress, status(audit.status));
  button.addEventListener("click", () => { state.selectedAuditId = audit.id; setView("audits"); renderAuditDetail(); });
  return button;
}

function renderDashboard() {
  renderMetrics();
  const recent = $("recent-audits");
  recent.replaceChildren(...state.workspace.audits.slice(0, 5).map(auditListItem));
  if (!state.workspace.audits.length) recent.append(element("div", "empty-state", "尚无审计制品或运行记录。"));
  const severity = state.workspace.summary.severity ?? {};
  const total = Math.max(1, Object.values(severity).reduce((sum, value) => sum + value, 0));
  const chart = $("severity-chart");
  const labels = { critical: "严重", high: "高危", medium: "中危", low: "低危", unknown: "未知" };
  chart.replaceChildren(...Object.entries(labels).map(([key, label]) => {
    const row = element("div", `severity-row ${key}`);
    const bar = element("span", "bar");
    const fill = element("i");
    fill.style.width = `${((severity[key] ?? 0) / total) * 100}%`;
    bar.append(fill);
    row.append(element("span", "", label), bar, element("strong", "", severity[key] ?? 0));
    return row;
  }));
}

function renderProjects() {
  const [value, body] = table(["项目", "Git 状态", "目标版本", "OpenCode 配置", "操作"]);
  for (const repository of state.repositories) {
    const row = element("tr");
    const identity = element("td");
    identity.append(element("strong", "", repository.name), element("small", "mono", repository.id));
    row.append(identity);
    const gitCell = element("td");
    gitCell.append(element("i", `health-dot ${repository.git_repository ? "ok" : ""}`), document.createTextNode(repository.git_repository ? (repository.dirty ? "存在本地修改" : "工作树干净") : "不是 Git 仓库"));
    row.append(gitCell);
    cell(row, `${repository.branch ?? "—"} · ${short(repository.commit)}`, "mono");
    cell(row, repository.configured ? "已就绪" : "缺少 .opencode/opencode.json");
    const action = element("td");
    const button = element("button", "text-button", "创建审计 →");
    button.disabled = !repository.configured || !state.runtime?.runner?.enabled;
    button.addEventListener("click", () => openAuditDialog(repository.id));
    action.append(button);
    row.append(action);
    body.append(row);
  }
  $("project-table").replaceChildren(value);
}

function renderAudits() {
  const [value, body] = table(["审计任务", "仓库 / 提交", "当前阶段", "进度", "漏洞", "状态"]);
  for (const audit of state.workspace.audits) {
    const row = element("tr", "clickable");
    const identity = element("td");
    identity.append(element("strong", "", audit.name), element("small", "mono", audit.id));
    row.append(identity);
    cell(row, `${audit.repository_name ?? "—"}\n${short(audit.commit)}`);
    cell(row, audit.stage);
    cell(row, `${audit.progress}%`);
    cell(row, audit.finding_count);
    const statusCell = element("td"); statusCell.append(status(audit.status)); row.append(statusCell);
    row.addEventListener("click", () => { state.selectedAuditId = audit.id; renderAuditDetail(); });
    body.append(row);
  }
  $("audit-table").replaceChildren(value);
  if (!state.selectedAuditId && state.workspace.audits[0]) state.selectedAuditId = state.workspace.audits[0].id;
  renderAuditDetail();
}

function renderAuditDetail() {
  const audit = state.workspace.audits.find(item => item.id === state.selectedAuditId);
  const panel = $("audit-detail");
  if (!audit) { panel.replaceChildren(element("div", "empty-state", "选择一个审计任务查看阶段详情。")); return; }
  const head = element("div");
  head.append(element("p", "eyebrow", "AUDIT SNAPSHOT"), element("h2", "", audit.name), element("p", "mono", audit.id), status(audit.status));
  const facts = element("dl", "detail-facts");
  [["仓库", audit.repository_name], ["提交", short(audit.commit, 18)], ["制品", `${audit.artifact_count} 个`], ["运行验证", `${audit.runtime_validation_count} 次`], ["更新时间", formatDate(audit.updated_at)], ["覆盖状态", audit.coverage?.status ?? "未生成"]].forEach(([label, value]) => {
    const wrapper = element("div"); wrapper.append(element("dt", "", label), element("dd", "", value ?? "—")); facts.append(wrapper);
  });
  const stages = element("ol", "stage-list");
  for (const stage of audit.stages ?? []) {
    const item = element("li", stage.state); item.append(element("i"), element("span", "", stage.label), element("small", "", stage.state === "completed" ? "完成" : stage.state === "active" ? "当前" : "等待")); stages.append(item);
  }
  const actions = element("div", "action-row");
  const available = audit.status === "running" ? ["pause", "cancel"] : audit.status === "paused" ? ["resume", "cancel"] : [];
  const labels = { pause: "暂停", resume: "恢复", cancel: "取消" };
  for (const action of available) {
    const button = element("button", `button ${action === "cancel" ? "secondary" : "primary"}`, labels[action]);
    button.addEventListener("click", () => requestAuditAction(audit, action));
    actions.append(button);
  }
  const logs = element("div", "runner-log");
  logs.append(element("p", "eyebrow", "RECENT AGENT OUTPUT"), element("pre", "", "正在读取最近输出…"));
  panel.replaceChildren(head, facts, stages, actions, logs);
  loadAuditLogs(audit.id, logs).catch(error => { logs.querySelector("pre").textContent = error.message; });
}

async function loadAuditLogs(auditId, container) {
  const items = (await api(`/api/v1/audits/${encodeURIComponent(auditId)}/logs?limit=80`)).items;
  if (state.selectedAuditId !== auditId) return;
  container.querySelector("pre").textContent = items.length ? items.map(item => `${item.occurred_at} [${item.source}] ${item.message}`).join("\n") : "当前没有 Runner 输出；历史制品审计不会生成进程日志。";
}

async function requestAuditAction(audit, action) {
  try {
    await api(`/api/v1/audits/${encodeURIComponent(audit.id)}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": `"${audit.version}"`, "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ action }),
    });
    toast(`已提交${({ pause: "暂停", resume: "恢复", cancel: "取消" })[action]}操作`);
    await load();
  } catch (error) { showError(error); }
}

function renderFindings() {
  const query = $("finding-query").value.trim().toLowerCase();
  const findings = state.workspace.findings.filter(item => !query || `${item.id} ${item.title} ${item.location.path ?? ""}`.toLowerCase().includes(query));
  const [value, body] = table(["等级", "漏洞发现", "审计 / 维度", "位置", "验证状态"]);
  for (const finding of findings) {
    const row = element("tr");
    cell(row, finding.severity, `severity ${finding.severity}`);
    const identity = element("td"); identity.append(element("strong", "", finding.title), element("small", "mono", finding.id)); row.append(identity);
    cell(row, `${finding.audit_id} · ${finding.dimension ?? "—"}`);
    cell(row, `${finding.location.path ?? "—"}${finding.location.line ? `:${finding.location.line}` : ""}`, "mono");
    const stateCell = element("td"); stateCell.append(status(finding.status)); row.append(stateCell);
    body.append(row);
  }
  $("finding-table").replaceChildren(value);
}

function renderReports() {
  const cards = state.workspace.reports.map(report => {
    const card = element("article", "report-card");
    card.append(element("p", "eyebrow", "SEALED MARKDOWN"), element("h3", "", report.name), element("p", "mono", report.path));
    const footer = element("footer", "", `${report.repository_name ?? "—"} · SHA-256 ${short(report.sha256, 16)} · ${bytes(report.size)} · ${formatDate(report.sealed_at)}`);
    card.append(footer);
    return card;
  });
  $("report-grid").replaceChildren(...cards);
  if (!cards.length) $("report-grid").append(element("div", "panel empty-state", "尚未发现最终封存报告。"));
}

function renderValidationList() {
  const list = $("validation-list");
  list.replaceChildren();
  for (const run of state.validationRuns) {
    const button = element("button", "audit-item");
    const identity = element("span"); identity.append(element("strong", "", `${run.audit_id} / ${run.finding_id}`), element("small", "", `${run.agent_name} · ${formatDate(run.recorded_at)}`));
    button.append(identity, status(run.verification_level ?? run.outcome));
    button.addEventListener("click", () => selectValidation(run.id));
    list.append(button);
  }
  if (!state.validationRuns.length) list.append(element("div", "empty-state", "尚无动态验证结果。"));
}

function renderValidationRequests() {
  const list = $("validation-request-list");
  const enabled = Boolean(state.runtime?.dynamic_runner?.enabled);
  $("dynamic-runner-caption").textContent = enabled ? "动态 Runner 已启用" : "只读模式";
  $("dynamic-runner-caption").className = `status ${enabled ? "running" : "artifact_only"}`;
  list.replaceChildren();
  for (const request of state.validationRequests) {
    const item = element("article", "request-item");
    const header = element("header");
    const identity = element("div");
    identity.append(element("h3", "", `${request.audit_id} / ${request.finding_id}`), element("small", "mono", request.vulnerability_type_id));
    header.append(identity, status(request.job?.status ?? (request.result_present ? "completed" : request.dispatch_ready ? "queued" : "failed")));
    item.append(header, element("p", "", request.summary ?? "没有保存验证请求摘要。"));
    const footer = element("footer");
    footer.append(element("span", "", `${request.repository_name} · ${short(request.source_commit)}`));
    const button = element("button", "button primary", request.job?.status === "running" ? "验证运行中" : request.result_present ? "已有结果" : "授权并启动");
    button.disabled = !enabled || !request.dispatch_ready || ["preparing", "running", "cancelling"].includes(request.job?.status);
    button.addEventListener("click", () => openValidationDialog(request));
    footer.append(button);
    item.append(footer);
    list.append(item);
  }
  if (!state.validationRequests.length) list.append(element("div", "empty-state", "没有发现密封的动态验证请求。"));
}

function exchangeText(exchange) {
  const requestHeaders = (exchange.request.headers ?? []).map(item => `${item.name}: ${item.value}`).join("\n");
  const requestBody = exchange.request.body?.text ?? "";
  const responseHeaders = (exchange.response.headers ?? []).map(item => `${item.name}: ${item.value}`).join("\n");
  const responseBody = exchange.response.body?.text ?? "";
  return `${exchange.request.method} ${exchange.request.url}\n${requestHeaders}${requestBody ? `\n\n${requestBody}` : ""}\n\nHTTP ${exchange.response.status ?? "ERR"} ${exchange.response.status_text ?? ""}\n${responseHeaders}${responseBody ? `\n\n${responseBody}` : ""}`;
}

async function selectValidation(id) {
  state.selectedValidationId = id;
  try {
    const run = (await api(`/api/runs/${encodeURIComponent(id)}`)).run;
    const panel = $("validation-detail");
    const header = element("div");
    header.append(element("p", "eyebrow", "RUNTIME RESULT"), element("h2", "", `${run.audit_id} / ${run.finding.id}`), element("p", "", run.finding.summary ?? "未保存漏洞摘要。"), status(run.finding.verification_level ?? run.finding.outcome));
    const facts = element("dl", "detail-facts");
    [["授权目标", run.environment.base_url], ["Subagent", run.actor.agent_name], ["浏览器", run.environment.browser_backend?.name], ["清理", run.finding.cleanup?.status], ["攻击者上下文", run.environment.attacker_context_id], ["受害者上下文", run.environment.victim_context_id]].forEach(([label, value]) => {
      const wrapper = element("div"); wrapper.append(element("dt", "", label), element("dd", "", value ?? "—")); facts.append(wrapper);
    });
    const exchanges = element("div", "exchange-list");
    for (const exchange of run.network.exchanges ?? []) {
      const detail = element("details", "exchange");
      detail.append(element("summary", "", `${exchange.sequence}. ${exchange.request.method} ${new URL(exchange.request.url).pathname} · ${exchange.response.status ?? "ERR"}`));
      detail.append(element("pre", "", exchangeText(exchange)));
      exchanges.append(detail);
    }
    if (!(run.network.exchanges ?? []).length) exchanges.append(element("div", "notice", run.network.warning ?? "未捕获 HTTP exchange。"));
    panel.replaceChildren(header, facts, exchanges);
  } catch (error) { showError(error); }
}

function renderRuntime() {
  const runner = state.runtime?.runner ?? {};
  const dynamicRunner = state.runtime?.dynamic_runner ?? {};
  $("runtime-grid").replaceChildren(
    metric("运行驱动", runner.enabled ? "已启用" : "只读", runner.enabled ? "可以提交 OpenCode 审计" : "使用 --enable-runner 开启"),
    metric("活跃进程", runner.active_processes ?? 0, "仅跟踪本服务启动的子进程"),
    metric("登记仓库", runner.registered_repositories ?? 0, "服务端白名单"),
    metric("审计制品", state.workspace.artifacts.length, "已解析的报告元数据"),
    metric("动态验证", dynamicRunner.enabled ? "已启用" : "只读", `${dynamicRunner.active_processes ?? 0} 个隔离会话`),
  );
}

function renderAll() {
  renderDashboard(); renderProjects(); renderAudits(); renderFindings(); renderReports(); renderValidationRequests(); renderValidationList(); renderRuntime();
  const enabled = Boolean(state.runtime?.runner?.enabled);
  $("runner-state").textContent = enabled ? "运行驱动已启用" : "只读观测模式";
  $("runner-pulse").classList.toggle("online", enabled);
  $("engine-caption").textContent = `${state.repositories.length} 个仓库 · ${state.workspace.artifacts.length} 个制品`;
  $("new-audit").disabled = !enabled;
  $("new-audit").title = enabled ? "创建审计" : "请使用 --enable-runner 启动服务";
}

function connectEventStream() {
  state.eventSource?.close();
  state.eventSource = null;
  const audit = state.workspace.audits.find(item => ["queued", "preparing", "running", "pausing", "paused", "cancelling"].includes(item.status));
  if (!audit || !state.runtime?.runner?.enabled) return;
  const source = new EventSource(`/api/v1/audits/${encodeURIComponent(audit.id)}/events?after=${audit.event_sequence ?? 0}`);
  state.eventSource = source;
  source.onmessage = () => {
    if (state.liveRefresh) return;
    state.liveRefresh = window.setTimeout(() => {
      state.liveRefresh = null;
      load().catch(showError);
    }, 800);
  };
}

function connectValidationEventStream() {
  state.validationEventSource?.close();
  state.validationEventSource = null;
  const request = state.validationRequests.find(item => ["preparing", "running", "cancelling"].includes(item.job?.status));
  if (!request || !state.runtime?.dynamic_runner?.enabled) return;
  const source = new EventSource(`/api/v1/validations/${encodeURIComponent(request.id)}/events?after=${request.job.event_sequence ?? 0}`);
  state.validationEventSource = source;
  source.onmessage = () => {
    if (state.validationLiveRefresh) return;
    state.validationLiveRefresh = window.setTimeout(() => {
      state.validationLiveRefresh = null;
      load().catch(showError);
    }, 800);
  };
}

function showError(error) {
  const value = $("global-error");
  value.textContent = error.message;
  value.hidden = false;
  toast(error.message);
}

async function load() {
  $("global-error").hidden = true;
  const [workspace, repositories, validation, validationRequests, runtime] = await Promise.all([
    api("/api/v1/workspace"), api("/api/v1/repositories"), api("/api/runs"), api("/api/v1/validation-requests"), api("/api/v1/runtime/health"),
  ]);
  state.workspace = workspace;
  state.repositories = repositories.items;
  state.validationRuns = validation.runs;
  state.validationRequests = validationRequests.items;
  state.runtime = runtime;
  renderAll();
  connectEventStream();
  connectValidationEventStream();
}

function openValidationDialog(request) {
  if (!state.runtime?.dynamic_runner?.enabled) { toast("动态验证 Runner 未启用。"); return; }
  const form = $("validation-form");
  form.reset();
  form.elements.validation_request_id.value = request.id;
  form.elements.repository_id.value = request.repository_id;
  $("validation-form-subtitle").textContent = `${request.audit_id} / ${request.finding_id} · ${request.vulnerability_type_id}`;
  $("validation-form-error").hidden = true;
  $("validation-dialog").showModal();
}

async function submitValidation(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const input = {
    validation_request_id: data.get("validation_request_id"),
    repository_id: data.get("repository_id"),
    target_base_url: data.get("target_base_url"),
    attacker_account: { username: data.get("attacker_username"), password: data.get("attacker_password") },
    victim_account: { username: data.get("victim_username"), password: data.get("victim_password") },
    login_instructions: data.get("login_instructions"),
    cleanup_instructions: data.get("cleanup_instructions"),
    explicit_authorization: data.get("explicit_authorization") === "on",
    test_environment: data.get("test_environment") === "on",
  };
  const button = $("submit-validation");
  button.disabled = true;
  try {
    const run = await api("/api/v1/validations", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify(input),
    });
    form.reset();
    $("validation-dialog").close();
    toast(`动态验证 ${run.audit_id}/${run.finding_id} 已启动`);
    await load();
  } catch (error) {
    $("validation-form-error").textContent = error.message;
    $("validation-form-error").hidden = false;
  } finally { button.disabled = false; }
}

function openAuditDialog(repositoryId = null) {
  if (!state.runtime?.runner?.enabled) { toast("运行驱动未启用，请以 --enable-runner 启动工作台。"); return; }
  const select = $("repository-select");
  select.replaceChildren(...state.repositories.filter(repo => repo.configured && repo.git_repository).map(repo => {
    const option = element("option", "", `${repo.name} · ${repo.branch ?? "HEAD"}`); option.value = repo.id; return option;
  }));
  if (repositoryId) select.value = repositoryId;
  $("audit-form").elements.audit_id.value = `audit-${new Date().toISOString().slice(0, 10).replaceAll("-", "")}-${Math.random().toString(36).slice(2, 7)}`;
  $("audit-form-error").hidden = true;
  $("audit-dialog").showModal();
}

async function submitAudit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const input = {
    name: data.get("name"), repository_id: data.get("repository_id"), audit_id: data.get("audit_id"), ref: data.get("ref"), allow_dirty: data.get("allow_dirty") === "on",
  };
  const button = $("submit-audit");
  button.disabled = true;
  try {
    const audit = await api("/api/v1/audits", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify(input),
    });
    $("audit-dialog").close();
    form.reset();
    state.selectedAuditId = audit.id;
    toast(`审计 ${audit.id} 已进入队列`);
    await load();
    setView("audits");
  } catch (error) {
    $("audit-form-error").textContent = error.message;
    $("audit-form-error").hidden = false;
  } finally { button.disabled = false; }
}

document.querySelectorAll(".nav button[data-view]").forEach(button => button.addEventListener("click", () => setView(button.dataset.view)));
document.querySelectorAll("[data-go]").forEach(button => button.addEventListener("click", () => setView(button.dataset.go)));
document.querySelectorAll("[data-open-audit]").forEach(button => button.addEventListener("click", () => openAuditDialog()));
document.querySelectorAll("[data-close-dialog]").forEach(button => button.addEventListener("click", () => $("audit-dialog").close()));
document.querySelectorAll("[data-close-validation]").forEach(button => button.addEventListener("click", () => $("validation-dialog").close()));
$("new-audit").addEventListener("click", () => openAuditDialog());
$("refresh").addEventListener("click", () => load().then(() => toast("制品与运行状态已刷新")).catch(showError));
$("finding-query").addEventListener("input", renderFindings);
$("audit-form").addEventListener("submit", submitAudit);
$("validation-form").addEventListener("submit", submitValidation);

load().catch(showError);
