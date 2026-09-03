const state = {
  workspace: { summary: {}, audits: [], findings: [], reports: [], artifacts: [], queue: { enabled: false, interval_hours: 1, concurrency: 1 } },
  repositories: [],
  validationRuns: [],
  validationRequests: [],
  requestExchanges: [],
  selectedRequestExchangeIds: new Set(),
  runtime: null,
  environment: { capabilities: [], components: [], platform: {}, configuration: {} },
  modelSettings: { selected_model: "default", options: [{ value: "default", label: "默认" }], sources: [], selection_available: true },
  selectedAuditId: null,
  selectedValidationId: null,
  selectedFindingResourceId: null,
  view: "dashboard",
  eventSource: null,
  liveRefresh: null,
  validationEventSource: null,
  validationLiveRefresh: null,
  liveLoad: null,
  terminalRefresh: null,
  terminalResize: null,
  terminalObserver: null,
  terminalGrid: null,
  terminalAuditId: null,
  pendingDeleteAuditId: null,
  pendingDeleteRepositoryId: null,
  pendingCancelValidationId: null,
  findings: [],
  findingPage: 1,
  findingTotal: 0,
  findingTotalPages: 1,
  findingLoaded: false,
  findingLoading: false,
  findingRequestSequence: 0,
  findingSearchTimer: null,
};

const VIEW_META = {
  dashboard: ["源码审计工作台", "安全态势 / 概览"],
  projects: ["审计项目", "资产管理 / 操作员指定目录"],
  audits: ["审计任务", "任务中心 / 端到端运行"],
  findings: ["漏洞发现", "风险中心 / canonical findings"],
  reports: ["审计报告", "交付中心 / 完整性记录"],
  validation: ["完整动态验证", "验证中心 / 人工 localhost 证据"],
  runtime: ["运行环境", "平台管理 / 能力与组件"],
  settings: ["设置", "平台管理 / 任务序列排队"],
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
    queued: "排队中", preparing: "准备中", recovering: "恢复中", running: "运行中", pausing: "正在暂停", paused: "已暂停", cancelling: "正在取消",
    interrupted: "已中断", cancelled: "已取消", completed: "已完成", failed: "失败", artifact_only: "历史制品", unvalidated: "未验证",
    supported_runtime: "运行时已证实", not_confirmed: "未证实", stored_cross_user: "跨用户存储型 XSS", stored_same_user: "同用户存储型 XSS",
    ready: "已就绪", warning: "需注意", blocked: "受阻", unavailable: "不可用",
    queue_active: "已激活", queue_inactive: "未激活",
    unreviewed: "未处理", confirmed: "已确认", rejected: "已排除", insufficient_evidence: "证据不足",
    awaiting_validation: "待动态验证", validated: "验证通过", validation_failed: "验证失败", validation_blocked: "验证受阻", reported: "已入报告",
    supported_static: "静态证实",
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

function todoStatusText(todo) {
  if (!todo?.total) return "尚未从 Focus Area 初始化";
  if (todo.finalization_ready || todo.complete) {
    const terminal = todo.terminal ?? ((todo.done ?? 0) + (todo.gap ?? 0) + (todo.failed ?? 0));
    const residual = todo.gap ? ` · GAP ${todo.gap}（已记录，可收尾）` : "";
    return `终态 ${terminal}/${todo.total} · DONE ${todo.done ?? 0}${residual}`;
  }
  return `完成 ${todo.done ?? 0}/${todo.total} · 运行 ${todo.running ?? 0} · 待领 ${todo.pending ?? 0}${todo.gap ? ` · GAP ${todo.gap}` : ""}${todo.failed ? ` · FAILED ${todo.failed}` : ""}`;
}

function contextRecoveryText(recovery) {
  if (!recovery) return "尚未触发";
  const labels = {
    observed: "已检测", interrupting: "正在收敛 Runner", "waiting-for-runner-exit": "等待 Runner 退出",
    "waiting-to-compact": "等待压缩", compacting: "正在执行 /compact", compacted: "压缩完成",
    recovering: "正在断点恢复", restarted: "已压缩并恢复", failed: "压缩或恢复失败",
    exhausted: "已达到 3 次恢复上限", blocked: "缺少 OpenCode session",
  };
  return `${labels[recovery.state] ?? recovery.state ?? "状态未知"} · ${recovery.attempts ?? 0}/3 次`;
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
  renderActiveView();
  if (view === "findings" && !state.findingLoaded && !state.findingLoading) loadFindingsPage(1).catch(showError);
  window.scrollTo(0, 0);
}

function invalidateFindings() {
  state.findingRequestSequence += 1;
  state.findings = [];
  state.findingPage = 1;
  state.findingTotal = 0;
  state.findingTotalPages = 1;
  state.findingLoaded = false;
  state.findingLoading = false;
}

function applyWorkspace(workspace) {
  const previousCount = Number(state.workspace?.summary?.finding_count ?? 0);
  const nextCount = Number(workspace?.summary?.finding_count ?? 0);
  state.workspace = workspace;
  if (previousCount !== nextCount) invalidateFindings();
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
    metric("审计任务", summary.audit_count ?? 0, `${summary.active_audits ?? 0} 个活跃或排队中`),
    metric("canonical 漏洞", summary.finding_count ?? 0, `${summary.severity?.critical ?? 0} 个严重`),
    metric("最终报告", summary.report_count ?? 0, "模型验证或摘要记录"),
    metric("动态验证", summary.validation_run_count ?? 0, "显式授权的 localhost 运行"),
    metric("审计项目", state.repositories.length, `${state.repositories.filter(repo => repo.ready).length} 个可启动审计`),
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
  const todo = audit.todo?.total ? ` · 本地任务 ${audit.todo.done}/${audit.todo.total}${audit.todo.gap ? `，${audit.todo.gap} GAP` : ""}` : "";
  progress.append(element("small", "", audit.status === "queued" ? "等待定时调度" : `${audit.stage} · ${audit.progress ?? 0}%${todo}`), bar);
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
  const [value, body] = table(["项目 / 指定目录", "就绪度", "Git / 目标版本", "审计活动", "审计引擎配置", "操作"]);
  for (const repository of state.repositories) {
    const row = element("tr");
    const identity = element("td");
    identity.append(element("strong", "", repository.name), element("small", "mono", repository.directory), element("small", "mono", repository.id));
    row.append(identity);
    const readiness = element("td");
    readiness.append(status(repository.readiness));
    if (repository.issues?.length) readiness.append(element("small", "repository-issues", repository.issues.join("；")));
    else if (repository.dirty) readiness.append(element("small", "repository-issues warning", "存在本地修改，默认阻止创建可复现审计。"));
    else readiness.append(element("small", "repository-issues", "指定目录与审计引擎检查通过。"));
    row.append(readiness);
    const gitCell = element("td");
    gitCell.append(element("strong", "", repository.git_repository ? (repository.dirty ? "工作树有修改" : "工作树干净") : "Git 不可用"), element("small", "mono", `${repository.branch ?? "—"} · ${short(repository.commit)}`));
    row.append(gitCell);
    const activity = element("td");
    activity.append(element("strong", "", `${repository.audit_count ?? 0} 次审计`), element("small", "", repository.active_audit_count ? `${repository.active_audit_count} 个正在运行` : repository.last_audit_at ? `最近 ${formatDate(repository.last_audit_at)}` : "尚无运行记录"));
    row.append(activity);
    cell(row, !repository.configured ? "缺少配置" : repository.config_valid ? "JSON 有效" : "JSON 无效");
    const action = element("td");
    const create = element("button", "text-button", "创建审计 →");
    create.disabled = !repository.ready || !state.runtime?.runner?.enabled;
    create.addEventListener("click", () => openAuditDialog(repository.id));
    const remove = element("button", "text-button danger-text", "删除项目");
    remove.disabled = repository.removable === false || (repository.audit_count ?? 0) > 0;
    remove.title = repository.removable === false
      ? "该项目由工作台启动参数管理，不能从网页删除。"
      : (repository.audit_count ?? 0) > 0 ? "请先删除该项目的全部审计任务。" : "只移除工作台登记，不删除源码目录。";
    remove.addEventListener("click", () => openDeleteProjectDialog(repository));
    action.className = "project-actions";
    action.append(create, remove);
    row.append(action);
    body.append(row);
  }
  if (!state.repositories.length) {
    const row = element("tr");
    const empty = element("td", "empty-state", "尚未登记审计项目。点击“指定目录”，填写工作台所在机器上的源码目录。");
    empty.colSpan = 6;
    row.append(empty);
    body.append(row);
  }
  $("project-table").replaceChildren(value);
}

function renderAudits() {
  const dispatchQueue = $("dispatch-queue");
  const queue = state.workspace.queue ?? {};
  const queued = queue.queued_count ?? state.workspace.audits.filter(audit => audit.status === "queued").length;
  const availableSlots = queue.available_slots ?? 0;
  dispatchQueue.disabled = !queue.enabled || !queued || !availableSlots;
  dispatchQueue.title = !queue.enabled
    ? "请先在设置中激活排队机制"
    : !queued
      ? "当前没有排队中的审计任务"
      : !availableSlots
        ? "当前并发名额已满"
        : "跳过队列间隔，按创建时间启动当前可用名额内的任务";
  const [value, body] = table(["审计任务", "仓库 / 提交", "当前阶段", "进度", "漏洞", "状态", "操作"]);
  for (const audit of state.workspace.audits) {
    const row = element("tr", "clickable");
    const identity = element("td");
    identity.append(element("strong", "", audit.name), element("small", "mono", audit.id));
    row.append(identity);
    cell(row, `${audit.repository_name ?? "—"}\n${short(audit.commit)}`);
    cell(row, audit.stage);
    cell(row, audit.status === "queued" ? "等待调度" : (audit.todo?.total ? `${audit.progress}% · 任务 ${audit.todo.done}/${audit.todo.total}` : `${audit.progress}%`));
    cell(row, audit.finding_count);
    const statusCell = element("td"); statusCell.append(status(audit.status)); row.append(statusCell);
    const actionCell = element("td");
    if (audit.status === "queued") {
      const start = element("button", "button primary", "立即开始");
      start.disabled = !state.runtime?.runner?.enabled;
      start.title = start.disabled
        ? "运行驱动未启用"
        : "人工立即启动：跳过队列间隔、激活状态和并发名额";
      start.addEventListener("click", event => {
        event.stopPropagation();
        requestAuditAction(audit, "dispatch");
      });
      actionCell.append(start);
    } else {
      actionCell.textContent = "—";
    }
    row.append(actionCell);
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
  const queuedModel = state.modelSettings?.selected_model;
  const modelForDisplay = audit.status === "queued" && queuedModel !== undefined
    ? (queuedModel === "default" ? null : queuedModel)
    : audit.model;
  const head = element("div");
  head.append(element("p", "eyebrow", "AUDIT SNAPSHOT"), element("h2", "", audit.name), element("p", "mono", audit.id), status(audit.status));
  const facts = element("dl", "detail-facts");
  [["仓库", audit.repository_name], ["提交", short(audit.commit, 18)], [audit.status === "queued" ? "OpenCode 模型（下次启动）" : "OpenCode 模型（本次启动）", modelForDisplay ?? "默认（不传 --model）"], ["制品", `${audit.artifact_count} 个`], ["队列状态", audit.status === "queued" ? (audit.queue?.mode === "recover" ? "断点恢复等待调度；可立即调度" : "等待定时调度；可立即调度") : "未排队"], ["本地调度任务", todoStatusText(audit.todo)], ["上下文 watchdog", contextRecoveryText(audit.context_window_recovery)], ["人工完整验证", `${audit.runtime_validation_count} 次`], ["补充说明", audit.task_context?.additional_instructions_enabled ? `已启用 · ${audit.task_context.additional_instructions_length} 字符` : "未启用"], ["快速动态", audit.task_context?.dynamic_validation_enabled ? "已授权（一次 / 最多 120 秒 / loopback）" : "未授权（直接静态三方）"], ["交付进度来源", audit.progress_source === "local-audit-todo" ? "本地调度队列" : audit.progress_source === "stage-delivery-manifest" ? "八环节物化清单" : "历史制品推断"], ["断点恢复", audit.recovery_count ? `${audit.recovery_count} 次 · ${formatDate(audit.last_recovered_at)}` : "尚未恢复"], ["更新时间", formatDate(audit.updated_at)], ["覆盖状态", audit.coverage?.status ?? "未生成"], ["工作台制品目录", audit.paths?.reports_root ?? "历史任务未记录"]].forEach(([label, value]) => {
    const wrapper = element("div"); wrapper.append(element("dt", "", label), element("dd", "", value ?? "—")); facts.append(wrapper);
  });
  const stages = element("ol", "stage-list");
  for (const stage of audit.stages ?? []) {
    const item = element("li", stage.state); item.append(element("i"), element("span", "", stage.label), element("small", "", stage.state === "completed" ? "完成" : stage.state === "active" ? "当前" : "等待")); stages.append(item);
  }
  const diagnostics = [...new Set([
    ...(audit.todo_completion?.errors ?? []),
    ...(audit.stage_delivery?.errors ?? []),
  ].filter(value => typeof value === "string" && value.trim()))];
  if (!diagnostics.length && audit.error) diagnostics.push(audit.error);
  const diagnosticPanel = diagnostics.length ? element("section", "audit-diagnostics") : null;
  if (diagnosticPanel) {
    diagnosticPanel.append(element("p", "eyebrow", "WATCHDOG DIAGNOSTICS"), element("h3", "", "交付件诊断"));
    const list = element("ol");
    for (const item of diagnostics) list.append(element("li", "", item));
    diagnosticPanel.append(list);
  }
  const actions = element("div", "action-row");
  if (audit.terminal) {
    const monitorLabel = audit.terminal.live ? "OpenCode 实时事件" : audit.terminal.status === "archived" ? "查看事件快照" : "事件监控状态";
    const monitor = element("button", "button secondary", monitorLabel);
    monitor.addEventListener("click", () => openTerminal(audit));
    actions.append(monitor);
  }
  const available = audit.status === "running" ? ["pause", "cancel"] : audit.status === "paused" ? ["resume", "cancel"] : [];
  const labels = { pause: "暂停", resume: "恢复", cancel: "取消" };
  for (const action of available) {
    const button = element("button", `button ${action === "cancel" ? "secondary" : "primary"}`, labels[action]);
    button.addEventListener("click", () => requestAuditAction(audit, action));
    actions.append(button);
  }
  if (audit.status === "queued") {
    const dispatch = element("button", "button primary", "立即开始");
    dispatch.disabled = !state.runtime?.runner?.enabled;
    dispatch.title = dispatch.disabled
      ? "运行驱动未启用"
      : "人工立即启动：跳过队列间隔、激活状态和并发名额";
    dispatch.addEventListener("click", () => requestAuditAction(audit, "dispatch"));
    actions.append(dispatch);
  }
  if (["failed", "interrupted", "cancelled"].includes(audit.status) && audit.repository_id) {
    const recover = element("button", "button primary", "断点恢复");
    recover.disabled = !state.runtime?.runner?.enabled;
    recover.title = recover.disabled ? "运行驱动未启用" : "沿用原 audit_id、工作区、制品和 OpenCode 会话继续";
    recover.addEventListener("click", () => requestAuditAction(audit, "recover"));
    actions.append(recover);
  }
  if (["queued", "failed", "interrupted", "cancelled", "completed", "artifact_only"].includes(audit.status) && audit.repository_id) {
    const retry = element("button", "button secondary", audit.status === "completed" ? "再次审计" : "新建重试");
    retry.addEventListener("click", () => openAuditDialog(audit.repository_id, audit));
    actions.append(retry);
    const remove = element("button", "button danger", "删除任务");
    remove.addEventListener("click", () => openDeleteAuditDialog(audit));
    actions.append(remove);
  }
  const logs = element("div", "runner-log");
  logs.append(element("p", "eyebrow", "RECENT OPENCODE EVENTS"), element("div", "agent-event-stream", "正在读取最近事件…"));
  panel.replaceChildren(head, facts, stages, ...(diagnosticPanel ? [diagnosticPanel] : []), actions, logs);
  loadAuditLogs(audit.id, logs).catch(error => { logs.querySelector(".agent-event-stream").textContent = error.message; });
}

function eventCode(title, value) {
  if (!value) return null;
  const details = element("details", "agent-event-details");
  details.append(element("summary", "", title), element("pre", "", value));
  return details;
}

function renderAgentEvent(item, recent) {
  const card = element("article", `agent-event ${item.kind ?? "raw"} ${recent ? "recent" : "historical"}`);
  const header = element("header");
  const identity = element("span", "agent-event-identity");
  identity.append(element("strong", "", item.label ?? "OpenCode 事件"));
  if (item.tool) identity.append(element("code", "", item.tool));
  header.append(identity);
  if (item.status) header.append(element("span", `agent-event-status ${item.status}`, item.status));
  header.append(element("time", "", formatDate(item.occurred_at)));
  card.append(header);
  if (item.body) card.append(element("pre", "agent-event-body", item.body));
  const input = eventCode("查看调用参数", item.detail);
  if (input) card.append(input);
  return card;
}

async function loadAuditLogs(auditId, container) {
  const items = (await api(`/api/v1/audits/${encodeURIComponent(auditId)}/logs?limit=80`)).items;
  if (state.selectedAuditId !== auditId) return;
  const output = container.querySelector(".agent-event-stream");
  if (!items.length) {
    output.textContent = "当前没有 Runner 输出；历史制品审计不会生成进程日志。";
    return;
  }
  const recentStart = Math.max(0, items.length - 12);
  const fragment = document.createDocumentFragment();
  items.forEach((item, index) => fragment.append(renderAgentEvent(item, index >= recentStart)));
  output.replaceChildren(fragment);
  window.requestAnimationFrame(() => { output.scrollTop = output.scrollHeight; });
}

function setTerminalStatus(payload) {
  const value = $("terminal-live-state");
  value.className = `status ${payload.live ? "ready" : payload.available ? "warning" : "unavailable"}`;
  value.textContent = payload.live ? "实时" : payload.available ? "已归档" : "不可用";
  const dimensions = payload.columns && payload.rows ? ` · ${payload.columns}×${payload.rows}` : "";
  $("terminal-target").textContent = payload.target ? `${payload.target}${dimensions}` : "尚未创建 OpenCode run 窗口";
  $("terminal-message").textContent = payload.message ?? "";
  $("terminal-output").textContent = payload.output || (payload.live ? "终端窗口当前没有文本输出。" : "没有可显示的终端画面。");
  const commandWrap = $("terminal-command-wrap");
  commandWrap.hidden = !payload.attach_command;
  $("terminal-command").textContent = payload.attach_command ?? "";
  const sessionWrap = $("opencode-session-wrap");
  sessionWrap.hidden = !payload.provider_session_id;
  $("opencode-session-id").textContent = payload.provider_session_id ?? "";
  $("opencode-session-command").textContent = payload.opencode_command ?? "";
}

function withTerminalSession(payload, auditId) {
  const audit = state.workspace.audits.find(item => item.id === auditId);
  const sessionId = payload.provider_session_id ?? audit?.provider_session_id ?? audit?.terminal?.provider_session_id ?? null;
  return {
    ...payload,
    provider_session_id: sessionId,
    opencode_command: payload.opencode_command ?? (sessionId ? `opencode -s ${sessionId}` : null),
  };
}

function terminalGridSize() {
  const output = $("terminal-output");
  const style = window.getComputedStyle(output);
  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d");
  if (!context) return null;
  context.font = style.font;
  const characterWidth = context.measureText("M").width;
  const lineHeight = Number.parseFloat(style.lineHeight);
  const width = output.clientWidth - Number.parseFloat(style.paddingLeft) - Number.parseFloat(style.paddingRight);
  const height = output.clientHeight - Number.parseFloat(style.paddingTop) - Number.parseFloat(style.paddingBottom);
  if (!(characterWidth > 0) || !(lineHeight > 0) || !(width > 0) || !(height > 0)) return null;
  return {
    columns: Math.min(320, Math.max(40, Math.floor(width / characterWidth))),
    rows: Math.min(120, Math.max(12, Math.floor(height / lineHeight))),
  };
}

async function syncTerminalSize(auditId, { force = false } = {}) {
  if (state.terminalAuditId !== auditId || !$("terminal-dialog").open) return null;
  const size = terminalGridSize();
  if (!size) return null;
  const signature = `${auditId}:${size.columns}x${size.rows}`;
  if (!force && state.terminalGrid === signature) return null;
  const payload = await api(`/api/v1/audits/${encodeURIComponent(auditId)}/terminal/resize`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(size),
  });
  if (state.terminalAuditId !== auditId || !$("terminal-dialog").open) return null;
  state.terminalGrid = signature;
  setTerminalStatus(payload);
  return payload;
}

function scheduleTerminalResize() {
  window.clearTimeout(state.terminalResize);
  if (!state.terminalAuditId || !$("terminal-dialog").open) return;
  const auditId = state.terminalAuditId;
  state.terminalResize = window.setTimeout(() => {
    state.terminalResize = null;
    syncTerminalSize(auditId).then(payload => {
      if (!payload) return;
      const output = $("terminal-output");
      output.scrollTop = output.scrollHeight;
    }).catch(() => {});
  }, 180);
}

function observeTerminalSize() {
  state.terminalObserver?.disconnect();
  state.terminalObserver = null;
  if (typeof ResizeObserver !== "function") return;
  state.terminalObserver = new ResizeObserver(() => scheduleTerminalResize());
  state.terminalObserver.observe($("terminal-output"));
}

async function refreshTerminal(auditId) {
  window.clearTimeout(state.terminalRefresh);
  state.terminalRefresh = null;
  const payload = withTerminalSession(await api(`/api/v1/audits/${encodeURIComponent(auditId)}/terminal`), auditId);
  if (state.terminalAuditId !== auditId || !$("terminal-dialog").open) return;
  setTerminalStatus(payload);
  const output = $("terminal-output");
  output.scrollTop = output.scrollHeight;
  if (payload.live) state.terminalRefresh = window.setTimeout(() => refreshTerminal(auditId).catch(showError), 1000);
}

function openTerminal(audit) {
  state.terminalAuditId = audit.id;
  $("terminal-title").textContent = `OpenCode · ${audit.name}`;
  $("terminal-subtitle").textContent = `${audit.id} · 只读 Runner 事件窗口；原生交互 TUI 请使用下方 OpenCode session 命令`;
  setTerminalStatus(withTerminalSession({ available: false, live: false, status: "connecting", target: audit.terminal?.target, output: "正在读取终端窗口…", message: audit.terminal?.message }, audit.id));
  $("terminal-dialog").showModal();
  state.terminalGrid = null;
  observeTerminalSize();
  syncTerminalSize(audit.id, { force: true }).catch(() => null).finally(() => refreshTerminal(audit.id).catch(showError));
}

function closeTerminal() {
  window.clearTimeout(state.terminalRefresh);
  window.clearTimeout(state.terminalResize);
  state.terminalObserver?.disconnect();
  state.terminalRefresh = null;
  state.terminalResize = null;
  state.terminalObserver = null;
  state.terminalGrid = null;
  state.terminalAuditId = null;
  $("terminal-dialog").close();
}

async function requestAuditAction(audit, action) {
  try {
    await api(`/api/v1/audits/${encodeURIComponent(audit.id)}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": `"${audit.version}"`, "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ action }),
    });
    toast(`已提交${({ pause: "暂停", resume: "恢复", recover: "断点恢复", cancel: "取消", dispatch: "立即开始" })[action]}操作`);
    await load();
  } catch (error) { showError(error); }
}

function openCancelValidationDialog(request) {
  state.pendingCancelValidationId = request.job?.id ?? null;
  $("cancel-validation-id").textContent = `${request.audit_id} / ${request.finding_id}`;
  $("cancel-validation-form-error").hidden = true;
  $("cancel-validation-dialog").showModal();
}

function closeCancelValidationDialog() {
  state.pendingCancelValidationId = null;
  $("cancel-validation-dialog").close();
}

async function submitCancelValidation(event) {
  event.preventDefault();
  const request = state.validationRequests.find(item => item.job?.id === state.pendingCancelValidationId);
  const error = $("cancel-validation-form-error");
  if (!request || request.job?.status !== "running") {
    error.textContent = "该动态验证已不在运行，请关闭后刷新。";
    error.hidden = false;
    return;
  }
  const button = $("submit-cancel-validation");
  button.disabled = true;
  try {
    await api(`/api/v1/validations/${encodeURIComponent(request.job.id)}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ action: "cancel" }),
    });
    closeCancelValidationDialog();
    toast("已提交停止动态验证操作");
    await load();
  } catch (requestError) {
    error.textContent = requestError.message;
    error.hidden = false;
  } finally { button.disabled = false; }
}

async function dispatchQueueNow() {
  const button = $("dispatch-queue");
  button.disabled = true;
  try {
    await api("/api/v1/settings/queue/dispatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    toast("队列已立即调度，已按 FIFO 补足可用并发名额");
    await load();
  } catch (error) { showError(error); }
}

function openDeleteAuditDialog(audit) {
  state.pendingDeleteAuditId = audit.id;
  $("delete-audit-id").textContent = audit.id;
  $("delete-audit-form-error").hidden = true;
  $("delete-audit-dialog").showModal();
}

function openDeleteProjectDialog(repository) {
  state.pendingDeleteRepositoryId = repository.id;
  $("delete-project-name").textContent = repository.name;
  $("delete-project-id").textContent = repository.id;
  $("delete-project-form-error").hidden = true;
  $("delete-project-dialog").showModal();
}

function closeDeleteProjectDialog() {
  state.pendingDeleteRepositoryId = null;
  $("delete-project-dialog").close();
}

async function submitDeleteProject(event) {
  event.preventDefault();
  const repository = state.repositories.find(item => item.id === state.pendingDeleteRepositoryId);
  const error = $("delete-project-form-error");
  if (!repository) {
    error.textContent = "待删除的审计项目已不存在，请关闭后刷新。";
    error.hidden = false;
    return;
  }
  const button = $("submit-delete-project");
  button.disabled = true;
  try {
    await api(`/api/v1/repositories/${encodeURIComponent(repository.id)}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirmation: repository.id }),
    });
    closeDeleteProjectDialog();
    toast(`已移除审计项目 ${repository.name}；源码目录未删除`);
    await load();
  } catch (requestError) {
    error.textContent = requestError.message;
    error.hidden = false;
  } finally { button.disabled = false; }
}

function closeDeleteAuditDialog() {
  state.pendingDeleteAuditId = null;
  $("delete-audit-dialog").close();
}

async function submitDeleteAudit(event) {
  event.preventDefault();
  const audit = state.workspace.audits.find(item => item.id === state.pendingDeleteAuditId);
  const error = $("delete-audit-form-error");
  if (!audit) {
    error.textContent = "待删除的审计任务已不存在，请关闭后刷新。";
    error.hidden = false;
    return;
  }
  const button = $("submit-delete-audit");
  button.disabled = true;
  try {
    const result = await api(`/api/v1/audits/${encodeURIComponent(audit.id)}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", "If-Match": `"${audit.version}"` },
      body: JSON.stringify({ confirmation: audit.id }),
    });
    closeDeleteAuditDialog();
    state.selectedAuditId = null;
    invalidateFindings();
    toast(`已删除 ${result.audit_id}`);
    await load();
  } catch (requestError) {
    error.textContent = requestError.message;
    error.hidden = false;
  } finally { button.disabled = false; }
}

function renderFindings() {
  const findings = state.findings;
  const value = element("div", "finding-card-list");
  const positioned = findings.filter(finding => finding.location_complete).length;
  if (state.findingLoading && !state.findingLoaded) {
    value.append(element("div", "empty-state", "正在加载第 1 页漏洞发现…"));
    $("finding-table").replaceChildren(value);
    return;
  }
  value.append(element("p", "finding-list-summary", `共 ${state.findingTotal} 条漏洞发现 · 第 ${state.findingPage}/${state.findingTotalPages} 页 · 本页 ${positioned}/${findings.length} 条已提供文件与行号定位。`));
  for (const finding of findings) {
    const card = element("article", `finding-card${finding.location_complete ? "" : " location-missing"}`);
    const header = element("header", "finding-card-header");
    const identity = element("div", "finding-card-identity");
    identity.append(element("span", `severity ${finding.severity}`, finding.severity), element("small", "mono", finding.id));
    const open = element("button", "finding-link", finding.title);
    open.type = "button";
    open.addEventListener("click", () => openFinding(finding));
    identity.append(open);
    const statuses = element("div", "finding-card-statuses");
    statuses.append(status(finding.workflow?.status ?? "unreviewed"), status(finding.status));
    header.append(identity, statuses);
    const locationText = finding.location?.path
      ? `${finding.location.path}${finding.location.line ? `:${finding.location.line}${finding.location.line_end ? `-${finding.location.line_end}` : ""}` : ""}`
      : "未提供源码定位";
    const location = element("p", `finding-card-location mono${finding.location_complete ? "" : " missing"}`, locationText);
    const summary = element("p", "finding-card-summary", finding.description || "未提供漏洞判断摘要。");
    const facts = element("div", "finding-card-facts");
    facts.append(
      element("span", "", `Repo：${finding.repository_name ?? "未知"}`),
      element("span", "", `审计：${finding.audit_id}`),
      element("span", "", `维度：${finding.dimension ?? "未标注"}`),
      element("span", "", `证据：${finding.evidence?.length ?? 0} 条`),
    );
    const footer = element("footer", "finding-card-footer");
    footer.append(element("small", "", finding.remediation ? `修复：${short(finding.remediation, 110)}` : "未提供修复建议"));
    const action = element("button", "button secondary", "查看证据与处理");
    action.addEventListener("click", () => openFinding(finding));
    footer.append(action);
    card.append(header, location, summary, facts, footer);
    value.append(card);
  }
  if (!findings.length) value.append(element("div", "empty-state", "没有符合条件的漏洞发现。"));
  if (state.findingTotal > 0) {
    const pagination = element("nav", "finding-pagination");
    pagination.setAttribute("aria-label", "漏洞发现分页");
    const previous = element("button", "button secondary", "上一页");
    previous.type = "button";
    previous.disabled = state.findingLoading || state.findingPage <= 1;
    previous.addEventListener("click", () => loadFindingsPage(state.findingPage - 1).catch(showError));
    const page = element("span", "", `第 ${state.findingPage} 页，共 ${state.findingTotalPages} 页`);
    const next = element("button", "button secondary", "下一页");
    next.type = "button";
    next.disabled = state.findingLoading || state.findingPage >= state.findingTotalPages;
    next.addEventListener("click", () => loadFindingsPage(state.findingPage + 1).catch(showError));
    pagination.append(previous, page, next);
    value.append(pagination);
  }
  $("finding-table").replaceChildren(value);
}

async function loadFindingsPage(page = 1) {
  const sequence = ++state.findingRequestSequence;
  state.findingLoading = true;
  renderFindings();
  try {
    const parameters = new URLSearchParams({ page: String(page) });
    const query = $("finding-query").value.trim();
    if (query) parameters.set("q", query);
    const payload = await api(`/api/v1/findings?${parameters}`);
    if (sequence !== state.findingRequestSequence) return;
    state.findings = payload.items;
    state.findingPage = payload.page;
    state.findingTotal = payload.count;
    state.findingTotalPages = payload.total_pages;
    state.findingLoaded = true;
  } finally {
    if (sequence === state.findingRequestSequence) {
      state.findingLoading = false;
      renderFindings();
    }
  }
}

function findingSection(label, value) {
  const section = element("section", "finding-section");
  section.append(element("h3", "", label), element("p", "", value ?? "未记录。"));
  return section;
}

function sourceLocationText(location) {
  if (!location?.path) return "未提供文件位置";
  return `${location.path}${location.line ? `:${location.line}${location.line_end ? `-${location.line_end}` : ""}` : ""}`;
}

function findingLocationsSection(finding) {
  const section = element("section", "finding-section");
  section.append(element("h3", "", "源码定位"));
  const locations = element("ol", "finding-location-list");
  for (const location of finding.locations ?? []) {
    const item = element("li");
    item.append(element("strong", "mono", sourceLocationText(location)));
    if (location.role) item.append(element("small", "", location.role));
    if (location.detail) item.append(element("p", "", location.detail));
    locations.append(item);
  }
  if (!locations.childElementCount) {
    locations.append(element("li", "missing", "该制品没有提供可用的源码定位；需要回查来源制品。"));
  }
  section.append(locations);
  return section;
}

function findingEvidenceSection(finding) {
  const section = element("section", "finding-section");
  section.append(element("h3", "", "关键证据"));
  const evidence = element("ol", "finding-evidence-list");
  for (const item of finding.evidence ?? []) {
    const entry = element("li");
    entry.append(element("strong", "", item.kind), element("p", "", item.text));
    if (item.location?.path) entry.append(element("small", "mono", sourceLocationText(item.location)));
    evidence.append(entry);
  }
  if (!evidence.childElementCount) evidence.append(element("li", "missing", "来源制品未提供结构化证据。"));
  section.append(evidence);
  return section;
}

function openFinding(finding) {
  state.selectedFindingResourceId = finding.resource_id;
  $("finding-detail-title").textContent = finding.title;
  $("finding-detail-subtitle").textContent = `${finding.repository_name ?? "未知 Repo"} · ${finding.audit_id} · ${finding.id}`;
  const facts = $("finding-detail-facts");
  facts.replaceChildren();
  [["关联 Repo", finding.repository_name], ["Repository ID", finding.repository_id], ["审计 ID", finding.audit_id], ["等级", finding.severity], ["CVSS", finding.cvss_score], ["维度", finding.dimension], ["漏洞类型", finding.vulnerability_type_id], ["主定位", sourceLocationText(finding.location)], ["处理状态", statusText(finding.workflow?.status)], ["验证状态", statusText(finding.status)], ["来源制品", finding.source_path]].forEach(([label, value]) => {
    const wrapper = element("div"); wrapper.append(element("dt", "", label), element("dd", "", value ?? "—")); facts.append(wrapper);
  });
  const sourceNote = finding.source_finding_ids?.length
    ? `关联来源：${finding.source_finding_ids.join("、")}。${finding.contradiction_count ? `存在 ${finding.contradiction_count} 条矛盾记录。` : "未记录矛盾。"}`
    : finding.contradiction_count ? `存在 ${finding.contradiction_count} 条矛盾记录。` : "未记录来源 finding 关联。";
  const impact = [finding.impact, finding.severity_rationale].filter(Boolean).join("\n") || null;
  const analysis = [finding.reachability && `可达性：${finding.reachability}`, finding.attacker_influence && `攻击者影响：${finding.attacker_influence}`, finding.guards && `已检查防护：${finding.guards}`].filter(Boolean).join("\n") || null;
  $("finding-detail-body").replaceChildren(
    findingSection("漏洞说明", finding.description),
    findingLocationsSection(finding),
    findingEvidenceSection(finding),
    findingSection("影响与严重性依据", impact),
    findingSection("可达性与防护", analysis),
    findingSection("修复建议", finding.remediation),
    findingSection("残余不确定性", finding.residual_uncertainty),
    findingSection("关联与矛盾", sourceNote),
  );
  const form = $("finding-workflow-form");
  form.elements.status.value = finding.workflow?.status ?? "unreviewed";
  form.elements.note.value = finding.workflow?.note ?? "";
  $("finding-workflow-version").textContent = `版本 ${finding.workflow?.version ?? 0}${finding.workflow?.updated_at ? ` · ${formatDate(finding.workflow.updated_at)}` : " · 尚未保存"}`;
  $("finding-workflow-error").hidden = true;
  $("finding-dialog").showModal();
}

function statusText(value) {
  const labels = {
    unreviewed: "未处理", confirmed: "已确认", rejected: "已排除", insufficient_evidence: "证据不足",
    awaiting_validation: "待动态验证", validated: "验证通过", validation_failed: "验证失败", validation_blocked: "验证受阻", reported: "已入报告", supported_static: "静态证实", supported_runtime: "运行时已证实", unvalidated: "未验证",
  };
  return labels[value] ?? value ?? "未处理";
}

async function submitFindingWorkflow(event) {
  event.preventDefault();
  const finding = state.findings.find(item => item.resource_id === state.selectedFindingResourceId);
  if (!finding) return;
  const form = event.currentTarget;
  const data = new FormData(form);
  const button = $("submit-finding-workflow");
  button.disabled = true;
  try {
    await api(`/api/v1/findings/${encodeURIComponent(finding.resource_id)}/workflow`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": `"${finding.workflow?.version ?? 0}"`, "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ status: data.get("status"), note: data.get("note") }),
    });
    toast(`漏洞 ${finding.id} 的处理状态已保存`);
    $("finding-dialog").close();
    await loadFindingsPage(state.findingPage);
  } catch (error) {
    $("finding-workflow-error").textContent = error.message;
    $("finding-workflow-error").hidden = false;
  } finally {
    button.disabled = false;
  }
}

function renderReports() {
  const cards = state.workspace.reports.map(report => {
    const card = element("article", "report-card");
    const integrity = report.integrity_state === "verified_model"
      ? ["MODEL VERIFIED", "模型与 Markdown 已完成确定性字节校验", "verified_model"]
      : report.integrity_state === "model_mismatch"
        ? ["MODEL MISMATCH", "报告模型或 Markdown 校验失败", "model_mismatch"]
        : ["DIGEST RECORD", "历史报告仅记录当前 SHA-256，未发现报告模型", "digest_only"];
    card.append(element("p", "eyebrow", integrity[0]), element("h3", "", report.name), element("p", "mono", report.path), element("span", `status ${integrity[2]}`, integrity[1]));
    const footer = element("footer", "", `${report.repository_name ?? "—"} · SHA-256 ${short(report.sha256, 16)} · ${bytes(report.size)} · ${formatDate(report.sealed_at)}`);
    const actions = element("div", "report-actions");
    const preview = element("button", "button primary", "查看报告");
    preview.type = "button";
    preview.addEventListener("click", () => openReport(report));
    const download = element("a", "button secondary", "下载 Markdown");
    download.href = `/api/v1/reports/${encodeURIComponent(report.id)}/download`;
    actions.append(preview, download);
    card.append(footer, actions);
    return card;
  });
  $("report-grid").replaceChildren(...cards);
  if (!cards.length) $("report-grid").append(element("div", "panel empty-state", "尚未发现最终封存报告。"));
}

async function openReport(report) {
  const dialog = $("report-dialog");
  $("report-title").textContent = report.name;
  $("report-subtitle").textContent = `${report.repository_name ?? "—"} · ${report.path}`;
  $("report-digest").textContent = report.sha256 ?? "—";
  const integrityLabels = { verified_model: "模型绑定并通过确定性字节校验", model_mismatch: "模型或 Markdown 校验失败", digest_only: "仅记录当前 SHA-256，未发现报告模型" };
  $("report-integrity").textContent = integrityLabels[report.integrity_state] ?? report.integrity_state ?? "未知";
  const note = $("report-integrity-note");
  note.hidden = report.integrity_state === "verified_model";
  note.textContent = report.integrity_state === "model_mismatch"
    ? `该报告不能作为模型绑定封存件使用。校验问题：${(report.integrity_issues ?? []).join("、") || "未知"}`
    : "该历史报告可以预览和下载，但当前只能证明本次读取内容与展示摘要一致，不能证明它来自确定性报告模型。";
  $("report-preview").textContent = "正在校验封存摘要并读取报告…";
  $("report-download").href = `/api/v1/reports/${encodeURIComponent(report.id)}/download`;
  dialog.showModal();
  try {
    const value = await api(`/api/v1/reports/${encodeURIComponent(report.id)}`);
    const preview = $("report-preview");
    if (value.rendering !== "markdown-it-html-disabled" || typeof value.rendered_html !== "string") throw new Error("服务端未返回可信的 Markdown 渲染结果。");
    preview.innerHTML = value.rendered_html;
  } catch (error) {
    $("report-preview").textContent = `报告读取失败：${error.message}`;
    showError(error);
  }
}

function renderValidationList() {
  const list = $("validation-list");
  list.replaceChildren();
  for (const run of state.validationRuns) {
    const button = element("button", "audit-item");
    const identity = element("span"); identity.append(element("strong", "", `${run.audit_id} / ${run.finding_id}`), element("small", "", `${run.agent_name} · ${formatDate(run.recorded_at)}`));
    button.append(identity, status(run.verification_level ?? run.outcome));
    button.addEventListener("click", () => selectValidation(run.resource_id ?? run.id));
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
    if (request.audit_managed && !request.task_test_environment_preconfigured && !request.result_present) {
      item.append(element("p", "request-guidance", "任务创建时未录入测试环境；可在本页授权表单中补录后启动完整动态验证。"));
    }
    if (request.dispatch_blocked_reason && !request.result_present) item.append(element("p", "request-blocker", request.dispatch_blocked_reason));
    if (request.job?.provider_session_id) {
      const session = element("p", "request-session");
      const command = `opencode -s ${request.job.provider_session_id}`;
      session.append(element("span", "", "OpenCode session："), element("code", "mono", command));
      const copy = element("button", "text-button", "复制命令");
      copy.type = "button";
      copy.addEventListener("click", async () => {
        await navigator.clipboard.writeText(command);
        toast("OpenCode session 命令已复制");
      });
      session.append(copy);
      item.append(session);
    }
    const footer = element("footer");
    footer.append(element("span", "", `${request.repository_name} · ${short(request.source_commit)}`));
    if (["running", "cancelling"].includes(request.job?.status)) {
      const stopButton = element("button", "button danger", request.job.status === "cancelling" ? "正在停止…" : "停止验证");
      stopButton.disabled = request.job.status === "cancelling";
      stopButton.addEventListener("click", () => openCancelValidationDialog(request));
      footer.append(stopButton);
    } else {
      const button = element("button", "button primary", request.result_present ? "已有结果" : request.task_test_environment_preconfigured ? "授权并启动" : "补录环境并启动");
      button.disabled = !enabled || !request.dispatch_ready || request.job?.status === "preparing";
      button.title = request.dispatch_blocked_reason ?? "";
      button.addEventListener("click", () => openValidationDialog(request));
      footer.append(button);
    }
    item.append(footer);
    list.append(item);
  }
  if (!state.validationRequests.length) list.append(element("div", "empty-state", "没有发现可进行完整动态验证的 Web 漏洞。"));
}

function exchangeText(exchange) {
  const requestHeaders = (exchange.request.headers ?? []).map(item => `${item.name}: ${item.value}`).join("\n");
  const requestBody = exchange.request.body?.text ?? "";
  const responseHeaders = (exchange.response.headers ?? []).map(item => `${item.name}: ${item.value}`).join("\n");
  const responseBody = exchange.response.body?.text ?? "";
  return `${exchange.request.method} ${exchange.request.url}\n${requestHeaders}${requestBody ? `\n\n${requestBody}` : ""}\n\nHTTP ${exchange.response.status ?? "ERR"} ${exchange.response.status_text ?? ""}\n${responseHeaders}${responseBody ? `\n\n${responseBody}` : ""}`;
}

async function copyExchange(exchange) {
  await navigator.clipboard.writeText(exchangeText(exchange));
  toast("脱敏请求/响应已复制");
}

async function downloadBruno(exchangeIds) {
  return downloadExchangeExport("/api/v1/http-exchanges/export/bruno", exchangeIds, "dynamic-validation-open-collection.zip", "OpenCollection");
}

async function downloadHar(exchangeIds) {
  return downloadExchangeExport("/api/v1/http-exchanges/export/har", exchangeIds, "dynamic-validation.har", "HAR");
}

async function downloadExchangeExport(path, exchangeIds, fallbackFilename, label) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ exchange_ids: exchangeIds }),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.message ?? `${label} 导出失败：HTTP ${response.status}`);
  }
  const disposition = response.headers.get("content-disposition") ?? "";
  const filename = disposition.match(/filename="([^"]+)"/)?.[1] ?? fallbackFilename;
  const objectUrl = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
  toast(`已导出 ${exchangeIds.length} 条请求的 ${label}`);
}

function filteredRequestExchanges() {
  const method = $("exchange-method-filter").value;
  const statusValue = $("exchange-status-filter").value.trim();
  const source = $("exchange-source-filter").value;
  const query = $("exchange-query-filter").value.trim().toLowerCase();
  return state.requestExchanges.filter(exchange => {
    if (method && exchange.request.method !== method) return false;
    if (statusValue && String(exchange.response?.status ?? "ERR") !== statusValue) return false;
    if (source && exchange.source !== source) return false;
    if (query && !`${exchange.exchange_id} ${exchange.request.url} ${exchange.request.body?.text ?? ""} ${exchange.response?.body?.text ?? ""}`.toLowerCase().includes(query)) return false;
    return true;
  });
}

function flattened(value, prefix = "") {
  if (Array.isArray(value)) return Object.fromEntries(value.flatMap((item, index) => Object.entries(flattened(item, `${prefix}[${index}]`))));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => Object.entries(flattened(item, prefix ? `${prefix}.${key}` : key))));
  return { [prefix || "value"]: value === null ? "null" : String(value ?? "") };
}

function compareSelectedExchanges() {
  const exchanges = [...state.selectedRequestExchangeIds].map(id => state.requestExchanges.find(exchange => exchange.exchange_id === id)).filter(Boolean);
  if (exchanges.length !== 2) return;
  const [left, right] = exchanges;
  const leftFields = flattened({ request: left.request, response: left.response, redirect_chain: left.redirect_chain });
  const rightFields = flattened({ request: right.request, response: right.response, redirect_chain: right.redirect_chain });
  const fields = [...new Set([...Object.keys(leftFields), ...Object.keys(rightFields)])].sort();
  const table = element("table");
  const head = element("tr");
  ["字段", left.exchange_id, right.exchange_id].forEach(label => head.append(element("th", "", label)));
  table.append(head);
  for (const field of fields) {
    const changed = leftFields[field] !== rightFields[field];
    const row = element("tr");
    row.append(element("td", "mono", field), element("td", changed ? "changed mono" : "mono", leftFields[field] ?? "—"), element("td", changed ? "changed mono" : "mono", rightFields[field] ?? "—"));
    table.append(row);
  }
  const panel = $("exchange-diff-panel");
  panel.replaceChildren(element("h3", "", "结构化差异预览"), table);
  panel.hidden = false;
}

function updateExchangeSelectionControls() {
  const selected = state.selectedRequestExchangeIds.size;
  const visible = filteredRequestExchanges();
  const all = visible.length > 0 && visible.every(exchange => state.selectedRequestExchangeIds.has(exchange.exchange_id));
  $("selected-exchange-count").textContent = `已选择 ${selected} 条`;
  $("export-selected-bruno").disabled = selected < 1;
  $("export-selected-har").disabled = selected < 1;
  $("compare-selected-exchanges").disabled = selected !== 2;
  $("clear-exchange-selection").disabled = selected < 1;
  $("select-all-exchanges").checked = all;
  $("select-all-exchanges").indeterminate = selected > 0 && !all;
  $("select-all-exchanges").disabled = visible.length < 1;
}

function renderRequestHistory() {
  const available = new Set(state.requestExchanges.map(exchange => exchange.exchange_id));
  state.selectedRequestExchangeIds = new Set([...state.selectedRequestExchangeIds].filter(id => available.has(id)));
  const list = $("request-exchange-list");
  list.replaceChildren();
  const visibleExchanges = filteredRequestExchanges();
  for (const exchange of visibleExchanges) {
    const row = element("div", "request-exchange-row");
    const selection = element("label", "request-exchange-selection");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = state.selectedRequestExchangeIds.has(exchange.exchange_id);
    checkbox.setAttribute("aria-label", `选择 ${exchange.request.method} ${exchange.request.url}`);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) state.selectedRequestExchangeIds.add(exchange.exchange_id);
      else state.selectedRequestExchangeIds.delete(exchange.exchange_id);
      updateExchangeSelectionControls();
    });
    selection.append(checkbox);
    const detail = element("details", "exchange request-exchange");
    const path = new URL(exchange.request.url).pathname;
    detail.append(element("summary", "", `${exchange.request.method} ${path} · ${exchange.response.status ?? "ERR"} · ${formatDate(exchange.started_at)}`));
    detail.append(element("pre", "", exchangeText(exchange)));
    const actions = element("div", "request-exchange-actions");
    const copy = element("button", "button secondary", "复制"); copy.type = "button"; copy.addEventListener("click", () => copyExchange(exchange).catch(showError));
    const exportBruno = element("button", "button secondary", "导出 OpenCollection"); exportBruno.type = "button"; exportBruno.addEventListener("click", () => downloadBruno([exchange.exchange_id]).catch(showError));
    actions.append(copy, exportBruno); detail.append(actions); row.append(selection, detail); list.append(row);
  }
  if (!visibleExchanges.length) list.append(element("div", "empty-state", state.requestExchanges.length ? "没有符合筛选条件的记录。" : "尚无 HTTP exchange 记录。"));
  updateExchangeSelectionControls();
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
    metric("运行驱动", runner.enabled ? "已启用" : "只读", runner.enabled ? "可以提交 OpenCode 审计" : "运行 start:audit-workbench:runner 开启"),
    metric("活跃进程", runner.active_processes ?? 0, "仅跟踪本服务启动的子进程"),
    metric("审计项目", runner.registered_repositories ?? 0, "操作员指定目录"),
    metric("审计制品", state.workspace.artifacts.length, "已解析的报告元数据"),
    metric("动态验证", dynamicRunner.enabled ? "已启用" : "只读", `${dynamicRunner.active_processes ?? 0} 个隔离会话`),
  );
  const capabilityGrid = $("capability-grid");
  capabilityGrid.replaceChildren(...(state.environment.capabilities ?? []).map(item => {
    const card = element("article", `capability-card ${item.status}`);
    card.append(element("span", "", item.label), element("strong", "", item.status === "ready" ? "可用" : "受阻"), element("small", "", item.status === "ready" ? item.summary : `缺少：${item.blockers.join("、")}`));
    return card;
  }));
  const [value, body] = table(["组件", "用途", "状态", "版本 / 命令", "说明"]);
  for (const component of state.environment.components ?? []) {
    const row = element("tr");
    cell(row, component.label);
    cell(row, component.category);
    const statusCell = element("td"); statusCell.append(status(component.status)); row.append(statusCell);
    cell(row, component.version ?? component.command ?? "—", "mono");
    cell(row, component.detail ?? "—");
    body.append(row);
  }
  $("environment-table").replaceChildren(value);
  const platform = state.environment.platform ?? {};
  $("environment-caption").textContent = `${platform.os ?? "未知系统"} / ${platform.arch ?? "未知架构"} · Node ${platform.node ?? "未知"} · ${state.environment.configuration?.valid ?? 0}/${state.environment.configuration?.checked ?? 0} 个配置有效`;
}

function renderSettings() {
  const model = state.modelSettings ?? { selected_model: "default", options: [{ value: "default", label: "默认" }], sources: [] };
  const modelForm = $("model-settings-form");
  const modelSelect = modelForm.elements.model;
  if (document.activeElement !== modelSelect) {
    const options = model.options ?? [];
    modelSelect.replaceChildren(...options.map(item => {
      const option = element("option", "", item.label); option.value = item.value; return option;
    }));
    if ([...modelSelect.options].some(option => option.value === model.selected_model)) modelSelect.value = model.selected_model;
    else modelSelect.value = "default";
  }
  const modelStatus = $("model-settings-status");
  modelStatus.className = `status ${model.selection_available === false ? "warning" : "ready"}`;
  modelStatus.textContent = model.selection_available === false ? "已选模型不可用" : model.selected_model === "default" ? "默认" : "已固定";
  const modelFacts = $("model-settings-facts");
  modelFacts.replaceChildren();
  [
    ["当前选择", model.selected_model === "default" ? "默认（不传 --model）" : model.selected_model],
    ["可选模型", `${Math.max(0, (model.options?.length ?? 1) - 1)} 个`],
    ["配置来源", (model.sources ?? []).map(source => `${source.path}（${source.status === "ready" ? `${source.model_count} 个模型` : source.status === "missing" ? "未配置" : "无效"}`).join("；") || "未配置"],
  ].forEach(([label, value]) => {
    const wrapper = element("div"); wrapper.append(element("dt", "", label), element("dd", label === "配置来源" ? "mono" : "", value)); modelFacts.append(wrapper);
  });
  const queue = state.workspace.queue ?? { enabled: false, interval_hours: 1, concurrency: 1 };
  const form = $("queue-settings-form");
  if (document.activeElement !== form.elements.interval_hours) form.elements.interval_hours.value = String(queue.interval_hours ?? 1);
  if (document.activeElement !== form.elements.concurrency) form.elements.concurrency.value = String(queue.concurrency ?? 1);
  const queueStatus = $("queue-status");
  queueStatus.className = `status ${queue.enabled ? "queue_active" : "queue_inactive"}`;
  queueStatus.textContent = queue.enabled ? "已激活" : "未激活";
  const toggle = $("toggle-queue");
  toggle.textContent = queue.enabled ? "停用排队机制" : "激活排队机制";
  const facts = $("queue-facts");
  facts.replaceChildren();
  [
    ["等待任务", `${queue.queued_count ?? 0} 个`],
    ["运行中任务", `${queue.active_count ?? 0} 个`],
    ["下轮计划启动", `${queue.next_batch_size ?? Math.min(queue.concurrency ?? 1, queue.queued_count ?? 0)} 个新任务`],
    ["上轮结果", `启动 ${queue.last_dispatch_started_count ?? 0} 个；失败 ${queue.last_dispatch_failed_count ?? 0} 个`],
    ["下次调度", queue.enabled ? formatDate(queue.next_dispatch_at) : "排队机制未激活"],
  ].forEach(([label, value]) => {
    const wrapper = element("div"); wrapper.append(element("dt", "", label), element("dd", "", value)); facts.append(wrapper);
  });
}

function renderShell() {
  const summary = state.workspace.summary;
  const enabled = Boolean(state.runtime?.runner?.enabled);
  $("runner-state").textContent = enabled ? "运行驱动已启用" : "只读观测模式";
  $("runner-pulse").classList.toggle("online", enabled);
  $("engine-caption").textContent = `${state.repositories.length} 个审计项目 · ${state.workspace.artifacts.length} 个制品`;
  $("new-audit").disabled = !enabled;
  $("new-audit").title = enabled ? "创建审计" : "请运行 npm --prefix .opencode run start:audit-workbench:runner";
  $("active-audit-badge").textContent = summary.active_audits ?? 0;
  $("finding-badge").textContent = summary.finding_count ?? 0;
}

function renderActiveView() {
  const renderers = {
    dashboard: renderDashboard,
    projects: renderProjects,
    audits: renderAudits,
    findings: renderFindings,
    reports: renderReports,
    validation: () => { renderRequestHistory(); renderValidationRequests(); renderValidationList(); },
    runtime: renderRuntime,
    settings: renderSettings,
  };
  renderers[state.view]?.();
  renderShell();
}

function connectEventStream() {
  state.eventSource?.close();
  state.eventSource = null;
  const audit = state.workspace.audits.find(item => ["queued", "preparing", "recovering", "running", "pausing", "paused", "cancelling"].includes(item.status));
  if (!audit || !state.runtime?.runner?.enabled) return;
  const source = new EventSource(`/api/v1/audits/${encodeURIComponent(audit.id)}/events?after=${audit.event_sequence ?? 0}`);
  state.eventSource = source;
  source.onmessage = () => {
    if (state.liveRefresh) return;
    state.liveRefresh = window.setTimeout(() => {
      state.liveRefresh = null;
      refreshLiveWorkspace().catch(showError);
    }, 800);
  };
}

function connectValidationEventStream() {
  state.validationEventSource?.close();
  state.validationEventSource = null;
  const request = state.validationRequests.find(item => ["preparing", "running", "cancelling"].includes(item.job?.status));
  if (!request || !state.runtime?.dynamic_runner?.enabled) return;
  const source = new EventSource(`/api/v1/validations/${encodeURIComponent(request.job.id)}/events?after=${request.job.event_sequence ?? 0}`);
  state.validationEventSource = source;
  source.onmessage = () => {
    if (state.validationLiveRefresh) return;
    state.validationLiveRefresh = window.setTimeout(() => {
      state.validationLiveRefresh = null;
      refreshLiveWorkspace().catch(showError);
    }, 800);
  };
}

function showError(error) {
  const value = $("global-error");
  value.textContent = error.message;
  value.hidden = false;
  toast(error.message);
}

async function refreshLiveWorkspace() {
  if (state.liveLoad) return state.liveLoad;
  const request = (async () => {
    $("global-error").hidden = true;
    const requests = [api("/api/v1/workspace")];
    // Validation has two supplementary collections.  Keep them current only
    // while that page is visible; status output from a static audit should not
    // repeatedly scan validation records or rebuild that page in the background.
    if (state.view === "validation") requests.push(api("/api/runs"), api("/api/v1/validation-requests"), api("/api/v1/http-exchanges?limit=100"));
    const [workspace, validation, validationRequests, exchanges] = await Promise.all(requests);
    applyWorkspace(workspace);
    if (validation) state.validationRuns = validation.runs;
    if (validationRequests) state.validationRequests = validationRequests.items;
    if (exchanges) state.requestExchanges = exchanges.items;
    renderActiveView();
    connectEventStream();
    connectValidationEventStream();
  })();
  state.liveLoad = request;
  try {
    return await request;
  } finally {
    if (state.liveLoad === request) state.liveLoad = null;
  }
}

async function load() {
  $("global-error").hidden = true;
  const [workspace, repositories, validation, validationRequests, runtime, environment, modelSettings, exchanges] = await Promise.all([
    api("/api/v1/workspace"), api("/api/v1/repositories"), api("/api/runs"), api("/api/v1/validation-requests"), api("/api/v1/runtime/health"), api("/api/v1/environment"), api("/api/v1/settings/model"), api("/api/v1/http-exchanges?limit=100"),
  ]);
  applyWorkspace(workspace);
  state.repositories = repositories.items;
  state.validationRuns = validation.runs;
  state.validationRequests = validationRequests.items;
  state.runtime = runtime;
  state.environment = environment;
  state.modelSettings = modelSettings.model;
  state.requestExchanges = exchanges.items;
  // Keep the initial paint small as well: hidden pages can contain long audit,
  // finding and report tables.  They are rendered when the operator opens them.
  renderActiveView();
  connectEventStream();
  connectValidationEventStream();
}

async function refreshEnvironment() {
  const button = $("refresh-environment");
  button.disabled = true;
  try {
    state.environment = await api("/api/v1/environment?refresh=1");
    renderRuntime();
    toast("运行环境探测已完成");
  } finally {
    button.disabled = false;
  }
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
    browser_mode: data.get("browser_mode"),
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

function syncAuditContextControls(form) {
  for (const [enabledName, textareaName] of [
    ["additional_instructions_enabled", "additional_instructions"],
    ["test_environment_enabled", "test_environment_context"],
  ]) {
    const checkbox = form.elements[enabledName];
    const textarea = form.elements[textareaName];
    const enabled = checkbox.checked;
    textarea.disabled = !enabled;
    textarea.required = enabled;
    textarea.closest("[data-context-option]")?.classList.toggle("enabled", enabled);
  }
}

function openAuditDialog(repositoryId = null, templateAudit = null) {
  if (!state.runtime?.runner?.enabled) { toast("运行驱动未启用，请运行 npm --prefix .opencode run start:audit-workbench:runner。"); return; }
  const form = $("audit-form");
  form.reset();
  const select = $("repository-select");
  select.replaceChildren(...state.repositories.filter(repo => repo.ready).map(repo => {
    const option = element("option", "", `${repo.name} · ${repo.branch ?? "HEAD"}`); option.value = repo.id; return option;
  }));
  if (!select.options.length) { toast("当前没有可启动审计的项目，请先指定目录或修复项目就绪度。" ); setView("projects"); return; }
  if (repositoryId) select.value = repositoryId;
  form.elements.name.value = templateAudit?.name ? `${templateAudit.name.replace(/（重试）$/u, "")}（重试）` : "";
  form.elements.audit_id.value = `audit-${new Date().toISOString().slice(0, 10).replaceAll("-", "")}-${Math.random().toString(36).slice(2, 7)}`;
  form.elements.ref.value = "HEAD";
  syncAuditContextControls(form);
  $("audit-form-error").hidden = true;
  $("audit-dialog").showModal();
}

function openProjectDialog() {
  const form = $("project-form");
  form.reset();
  $("project-form-error").hidden = true;
  $("project-dialog").showModal();
}

async function submitProject(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const button = $("submit-project");
  button.disabled = true;
  try {
    const repository = await api("/api/v1/repositories", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ path: data.get("path"), name: data.get("name") }),
    });
    $("project-dialog").close();
    form.reset();
    toast(`审计项目 ${repository.name} 已登记`);
    await load();
    setView("projects");
  } catch (error) {
    $("project-form-error").textContent = error.message;
    $("project-form-error").hidden = false;
  } finally { button.disabled = false; }
}

async function submitAudit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const additionalInstructionsEnabled = form.elements.additional_instructions_enabled.checked;
  const testEnvironmentEnabled = form.elements.test_environment_enabled.checked;
  const input = {
    name: data.get("name"), repository_id: data.get("repository_id"), audit_id: data.get("audit_id"), ref: data.get("ref"), allow_dirty: data.get("allow_dirty") === "on",
    additional_instructions_enabled: additionalInstructionsEnabled,
    additional_instructions: additionalInstructionsEnabled ? form.elements.additional_instructions.value : "",
    test_environment_enabled: testEnvironmentEnabled,
    test_environment_context: testEnvironmentEnabled ? form.elements.test_environment_context.value : "",
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
    syncAuditContextControls(form);
    state.selectedAuditId = audit.id;
    toast(`审计 ${audit.id} 已进入队列`);
    await load();
    setView("audits");
  } catch (error) {
    $("audit-form-error").textContent = error.message;
    $("audit-form-error").hidden = false;
  } finally { button.disabled = false; }
}

async function submitQueueSettings(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const input = {
    interval_hours: Number(form.elements.interval_hours.value),
    concurrency: Number(form.elements.concurrency.value),
  };
  const button = $("save-queue-settings");
  button.disabled = true;
  $("queue-settings-error").hidden = true;
  try {
    await api("/api/v1/settings/queue", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    toast("任务队列设置已保存");
    await load();
  } catch (error) {
    $("queue-settings-error").textContent = error.message;
    $("queue-settings-error").hidden = false;
  } finally { button.disabled = false; }
}

async function submitModelSettings(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $("save-model-settings");
  button.disabled = true;
  $("model-settings-error").hidden = true;
  try {
    const response = await api("/api/v1/settings/model", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: form.elements.model.value }),
    });
    state.modelSettings = response.model;
    renderSettings();
    toast("OpenCode 模型设置已保存；未开始、重试和断点恢复任务会在启动时使用该选择");
  } catch (error) {
    $("model-settings-error").textContent = error.message;
    $("model-settings-error").hidden = false;
  } finally { button.disabled = false; }
}

async function toggleQueue() {
  const enabled = Boolean(state.workspace.queue?.enabled);
  const button = $("toggle-queue");
  button.disabled = true;
  $("queue-settings-error").hidden = true;
  try {
    await api(`/api/v1/settings/queue/${enabled ? "deactivate" : "activate"}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    toast(enabled ? "排队机制已停用；已运行任务不会被取消" : "排队机制已激活");
    await load();
  } catch (error) {
    $("queue-settings-error").textContent = error.message;
    $("queue-settings-error").hidden = false;
  } finally { button.disabled = false; }
}

document.querySelectorAll(".nav button[data-view]").forEach(button => button.addEventListener("click", () => setView(button.dataset.view)));
document.querySelectorAll("[data-go]").forEach(button => button.addEventListener("click", () => setView(button.dataset.go)));
document.querySelectorAll("[data-open-audit]").forEach(button => button.addEventListener("click", () => openAuditDialog()));
document.querySelectorAll("[data-close-dialog]").forEach(button => button.addEventListener("click", () => $("audit-dialog").close()));
document.querySelectorAll("[data-close-project]").forEach(button => button.addEventListener("click", () => $("project-dialog").close()));
document.querySelectorAll("[data-close-validation]").forEach(button => button.addEventListener("click", () => $("validation-dialog").close()));
document.querySelectorAll("[data-close-report]").forEach(button => button.addEventListener("click", () => $("report-dialog").close()));
document.querySelectorAll("[data-close-finding]").forEach(button => button.addEventListener("click", () => $("finding-dialog").close()));
document.querySelectorAll("[data-close-terminal]").forEach(button => button.addEventListener("click", closeTerminal));
document.querySelectorAll("[data-close-delete-audit]").forEach(button => button.addEventListener("click", closeDeleteAuditDialog));
document.querySelectorAll("[data-close-delete-project]").forEach(button => button.addEventListener("click", closeDeleteProjectDialog));
document.querySelectorAll("[data-close-cancel-validation]").forEach(button => button.addEventListener("click", closeCancelValidationDialog));
$("new-audit").addEventListener("click", () => openAuditDialog());
$("add-project").addEventListener("click", openProjectDialog);
$("refresh").addEventListener("click", () => load().then(() => toast("制品与运行状态已刷新")).catch(showError));
$("dispatch-queue").addEventListener("click", () => dispatchQueueNow().catch(showError));
$("finding-query").addEventListener("input", () => {
  window.clearTimeout(state.findingSearchTimer);
  state.findingSearchTimer = window.setTimeout(() => loadFindingsPage(1).catch(showError), 300);
});
$("audit-form").addEventListener("submit", submitAudit);
$("model-settings-form").addEventListener("submit", submitModelSettings);
$("queue-settings-form").addEventListener("submit", submitQueueSettings);
$("toggle-queue").addEventListener("click", () => toggleQueue().catch(showError));
for (const checkbox of $("audit-form").querySelectorAll(".enable-switch input[type=checkbox]")) {
  checkbox.addEventListener("change", () => syncAuditContextControls($("audit-form")));
}
$("project-form").addEventListener("submit", submitProject);
$("validation-form").addEventListener("submit", submitValidation);
$("select-all-exchanges").addEventListener("change", event => {
  const visibleIds = filteredRequestExchanges().map(exchange => exchange.exchange_id);
  if (event.currentTarget.checked) state.selectedRequestExchangeIds = new Set([...state.selectedRequestExchangeIds, ...visibleIds]);
  else for (const id of visibleIds) state.selectedRequestExchangeIds.delete(id);
  renderRequestHistory();
});
$("clear-exchange-selection").addEventListener("click", () => {
  state.selectedRequestExchangeIds.clear();
  renderRequestHistory();
});
$("export-selected-bruno").addEventListener("click", () => downloadBruno([...state.selectedRequestExchangeIds]).catch(showError));
$("export-selected-har").addEventListener("click", () => downloadHar([...state.selectedRequestExchangeIds]).catch(showError));
$("compare-selected-exchanges").addEventListener("click", compareSelectedExchanges);
for (const id of ["exchange-method-filter", "exchange-status-filter", "exchange-source-filter", "exchange-query-filter"]) {
  $(id).addEventListener(id.includes("filter") ? "input" : "change", renderRequestHistory);
}
$("finding-workflow-form").addEventListener("submit", submitFindingWorkflow);
$("delete-audit-form").addEventListener("submit", submitDeleteAudit);
$("delete-project-form").addEventListener("submit", submitDeleteProject);
$("cancel-validation-form").addEventListener("submit", submitCancelValidation);
$("refresh-environment").addEventListener("click", () => refreshEnvironment().catch(showError));
$("refresh-terminal").addEventListener("click", () => state.terminalAuditId && refreshTerminal(state.terminalAuditId).catch(showError));
window.addEventListener("resize", scheduleTerminalResize);

load().catch(showError);
