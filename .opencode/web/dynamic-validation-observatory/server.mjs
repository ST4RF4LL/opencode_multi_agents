#!/usr/bin/env node

import { createServer as createHttpServer } from "node:http";
import { createHash } from "node:crypto";
import { readFile, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import MarkdownIt from "markdown-it";
import { AuditQueueScheduler, QueueSettingsStore } from "./audit-queue-scheduler.mjs";
import { AuditRunner } from "./audit-runner.mjs";
import { EnvironmentHealthService } from "./environment-health.mjs";
import { FindingWorkflowStore } from "./finding-workflow.mjs";
import { listValidationRequests, listValidationRunDetails, listValidationRuns } from "./model.mjs";
import { DEFAULT_MODEL_SELECTION, OpenCodeModelCatalog, OpenCodeModelSettingsStore } from "./opencode-model-settings.mjs";
import { buildWorkspaceSnapshot } from "./workspace-model.mjs";
import { DynamicValidationRunner } from "./validation-runner.mjs";
import { RequestHistoryStore } from "./request-history-store.mjs";
import { buildOpenCollectionArchive } from "./bruno-exporter.mjs";
import { buildHar } from "./har-exporter.mjs";
import { materializeManualValidationRequests } from "./manual-validation-request-materializer.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(HERE, "../../..");
const PUBLIC_ROOT = join(HERE, "public");
const DEFAULT_RUNTIME_ROOT = join(PROJECT_ROOT, "reports", "validation-handoff", "runtime");
const DEFAULT_STATE_ROOT = join(PROJECT_ROOT, "reports", "platform", "audit-runs");
const DEFAULT_OPENCODE_CONFIG = join(PROJECT_ROOT, ".opencode", "opencode.json");
const DEFAULT_STAGE_REGISTRY = join(PROJECT_ROOT, ".opencode", "skills", "common-subagent", "audit-artifact-management", "contracts", "stage-agent-contracts.json");
const DEFAULT_ROLES = join(PROJECT_ROOT, ".opencode", "agent-manifest", "roles.json");
const BIND_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"]);
const MAX_REQUEST_BODY = 64 * 1024;
const MAX_REPORT_BODY = 8 * 1024 * 1024;
const FINDINGS_PAGE_SIZE = 50;
const markdownRenderer = new MarkdownIt({ html: false, linkify: false, typographer: false, breaks: false });
const defaultLinkOpen = markdownRenderer.renderer.rules.link_open
  ?? ((tokens, index, options, _environment, self) => self.renderToken(tokens, index, options));
markdownRenderer.renderer.rules.link_open = (tokens, index, options, environment, self) => {
  tokens[index].attrSet("rel", "noopener noreferrer");
  return defaultLinkOpen(tokens, index, options, environment, self);
};
const STATIC_FILES = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/index.html", ["index.html", "text/html; charset=utf-8"]],
  ["/app.js", ["app.js", "text/javascript; charset=utf-8"]],
  ["/styles.css", ["styles.css", "text/css; charset=utf-8"]],
  ["/logo_DJ.png", ["logo_DJ.png", "image/png"]],
]);

function json(response, status, value, headers = {}) {
  const body = `${JSON.stringify(value)}\n`;
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    ...headers,
  });
  response.end(body);
}

function binary(response, status, body, contentType, filename) {
  response.writeHead(status, {
    "Content-Type": contentType,
    "Content-Length": body.length,
    "Content-Disposition": `attachment; filename="${filename.replaceAll('"', '')}"`,
    "Cache-Control": "no-store",
  });
  response.end(body);
}

function securityHeaders(response) {
  response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
}

async function staticResponse(response, pathname) {
  const entry = STATIC_FILES.get(pathname);
  if (!entry) return false;
  const [fileName, contentType] = entry;
  const body = await readFile(join(PUBLIC_ROOT, fileName));
  response.writeHead(200, {
    "Content-Type": contentType,
    "Content-Length": body.length,
    "Cache-Control": "no-cache",
  });
  response.end(body);
  return true;
}

async function requestJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_REQUEST_BODY) throw Object.assign(new Error("请求体过大。"), { statusCode: 413, code: "request-too-large" });
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    throw Object.assign(new Error("请求体不是有效 JSON。"), { statusCode: 400, code: "invalid-json" });
  }
}

function assertSafeMutation(request) {
  if (!String(request.headers["content-type"] ?? "").toLowerCase().startsWith("application/json")) {
    throw Object.assign(new Error("写接口只接受 application/json。"), { statusCode: 415, code: "content-type-required" });
  }
  const origin = request.headers.origin;
  if (origin && origin !== `http://${request.headers.host}`) {
    throw Object.assign(new Error("拒绝跨站写请求。"), { statusCode: 403, code: "cross-origin-mutation-rejected" });
  }
}

function matchAuditPath(pathname, suffix = "") {
  const pattern = suffix
    ? new RegExp(`^/api/v1/audits/([^/]+)/${suffix}$`)
    : /^\/api\/v1\/audits\/([^/]+)$/;
  const match = pathname.match(pattern);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchReportPath(pathname, suffix = "") {
  const pattern = suffix
    ? new RegExp(`^/api/v1/reports/([^/]+)/${suffix}$`)
    : /^\/api\/v1\/reports\/([^/]+)$/;
  const match = pathname.match(pattern);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchFindingWorkflowPath(pathname) {
  const match = pathname.match(/^\/api\/v1\/findings\/([^/]+)\/workflow$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function scopedResourceId(repositoryId, localId) {
  return createHash("sha256").update(`${repositoryId}\0${localId}`).digest("hex").slice(0, 24);
}

function isWithin(root, candidate) {
  const value = relative(root, candidate);
  return value !== "" && !value.startsWith(`..${sep}`) && value !== ".." && !isAbsolute(value);
}

function filterFindings(findings, url) {
  const auditId = url.searchParams.get("audit_id");
  const severity = url.searchParams.get("severity")?.toUpperCase();
  const query = url.searchParams.get("q")?.trim().toLowerCase();
  return findings.filter(finding => {
    if (auditId && finding.audit_id !== auditId) return false;
    if (severity && finding.severity !== severity) return false;
    if (query && !`${finding.id} ${finding.title} ${finding.description ?? ""} ${finding.repository_name ?? ""} ${finding.repository_id ?? ""} ${finding.audit_id ?? ""} ${finding.location?.path ?? ""} ${(finding.evidence ?? []).map(item => item.text ?? "").join(" ")}`.toLowerCase().includes(query)) return false;
    return true;
  });
}

export function paginateFindings(findings, url) {
  const filtered = filterFindings(findings, url);
  const totalPages = Math.max(1, Math.ceil(filtered.length / FINDINGS_PAGE_SIZE));
  const requestedPage = Number.parseInt(url.searchParams.get("page") ?? "1", 10);
  const page = Math.min(Number.isInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1, totalPages);
  const start = (page - 1) * FINDINGS_PAGE_SIZE;
  return {
    items: filtered.slice(start, start + FINDINGS_PAGE_SIZE),
    count: filtered.length,
    returned_count: Math.min(FINDINGS_PAGE_SIZE, Math.max(0, filtered.length - start)),
    page,
    page_size: FINDINGS_PAGE_SIZE,
    total_pages: totalPages,
  };
}

function mergeSnapshots(snapshots) {
  const merged = {
    generated_at: new Date().toISOString(),
    summary: { audit_count: 0, active_audits: 0, completed_audits: 0, finding_count: 0, report_count: 0, validation_run_count: 0, severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } },
    audits: [], findings: [], reports: [], artifacts: [],
  };
  for (const snapshot of snapshots) {
    merged.audits.push(...snapshot.audits);
    merged.findings.push(...snapshot.findings);
    merged.reports.push(...snapshot.reports);
    merged.artifacts.push(...snapshot.artifacts);
    for (const key of Object.keys(merged.summary.severity)) merged.summary.severity[key] += snapshot.summary.severity[key] ?? 0;
  }
  merged.audits.sort((a, b) => String(b.updated_at ?? "").localeCompare(String(a.updated_at ?? "")));
  merged.summary.audit_count = merged.audits.length;
  merged.summary.active_audits = merged.audits.filter(audit => ["queued", "preparing", "recovering", "running", "pausing", "paused", "cancelling"].includes(audit.status)).length;
  merged.summary.completed_audits = merged.audits.filter(audit => audit.status === "completed").length;
  merged.summary.finding_count = merged.findings.length;
  merged.summary.report_count = merged.reports.length;
  merged.summary.validation_run_count = snapshots.reduce((total, snapshot) => total + snapshot.summary.validation_run_count, 0);
  return merged;
}

async function streamAuditEvents(request, response, runner, auditId) {
  if (!runner.getAudit(auditId)) {
    json(response, 404, { error: "audit-not-found" });
    return;
  }
  response.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  const prior = await runner.eventsSince(auditId, 0);
  const streamUrl = new URL(request.url ?? "/", "http://127.0.0.1");
  const afterSequence = Number(streamUrl.searchParams.get("after") ?? 0);
  const lastEventId = request.headers["last-event-id"];
  const lastIndex = lastEventId ? prior.findIndex(event => event.event_id === lastEventId) : -1;
  const replay = lastIndex >= 0 ? prior.slice(lastIndex + 1) : prior.filter(event => event.sequence > afterSequence);
  for (const event of replay) response.write(`id: ${event.event_id}\ndata: ${JSON.stringify(event)}\n\n`);
  const unsubscribe = runner.subscribe(auditId, event => response.write(`id: ${event.event_id}\ndata: ${JSON.stringify(event)}\n\n`));
  const heartbeat = setInterval(() => response.write(": heartbeat\n\n"), 15_000);
  heartbeat.unref();
  request.once("close", () => {
    clearInterval(heartbeat);
    unsubscribe();
  });
}

async function streamValidationEvents(request, response, runner, validationId) {
  if (!runner.getRun(validationId)) {
    json(response, 404, { error: "validation-not-found" });
    return;
  }
  response.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  const streamUrl = new URL(request.url ?? "/", "http://127.0.0.1");
  const afterSequence = Number(streamUrl.searchParams.get("after") ?? 0);
  for (const event of await runner.eventsSince(validationId, afterSequence)) response.write(`id: ${event.event_id}\ndata: ${JSON.stringify(event)}\n\n`);
  const unsubscribe = runner.subscribe(validationId, event => response.write(`id: ${event.event_id}\ndata: ${JSON.stringify(event)}\n\n`));
  const heartbeat = setInterval(() => response.write(": heartbeat\n\n"), 15_000);
  heartbeat.unref();
  request.once("close", () => { clearInterval(heartbeat); unsubscribe(); });
}

export function createAuditWorkbenchServer({
  runtimeRoot = DEFAULT_RUNTIME_ROOT,
  stateRoot = DEFAULT_STATE_ROOT,
  repositories = [],
  platformConfigPath = DEFAULT_OPENCODE_CONFIG,
  legacyRuntimeRoot = false,
  runnerEnabled = false,
  runner: suppliedRunner = null,
  dynamicRunnerEnabled = false,
  dynamicStateRoot = null,
  dynamicRunner: suppliedDynamicRunner = null,
  environmentService: suppliedEnvironmentService = null,
  findingStateRoot = null,
  findingWorkflow: suppliedFindingWorkflow = null,
  queueSettingsPath = null,
  queueSettingsStore: suppliedQueueSettingsStore = null,
  queueScheduler: suppliedQueueScheduler = null,
  modelSettingsPath = null,
  modelSettingsStore: suppliedModelSettingsStore = null,
  modelCatalog: suppliedModelCatalog = null,
  modelConfigPaths = null,
  requestStateRoot = null,
  requestHistoryStore: suppliedRequestHistoryStore = null,
} = {}) {
  const resolvedRuntimeRoot = resolve(runtimeRoot);
  const runner = suppliedRunner ?? new AuditRunner({ stateRoot, platformRoot: PROJECT_ROOT, repositories, configPath: platformConfigPath, enabled: runnerEnabled });
  const queueSettingsStore = suppliedQueueSettingsStore ?? new QueueSettingsStore({
    path: queueSettingsPath ?? join(dirname(resolve(stateRoot)), "workbench-settings.json"),
  });
  const queueScheduler = suppliedQueueScheduler ?? new AuditQueueScheduler({ runner, settingsStore: queueSettingsStore });
  runner.setQueueScheduler(queueScheduler);
  const xdgConfigHome = resolve(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"));
  const modelCatalog = suppliedModelCatalog ?? new OpenCodeModelCatalog({
    configPaths: modelConfigPaths ?? [
      resolve(platformConfigPath),
      resolve(dirname(platformConfigPath), "opencode.jsonc"),
      join(xdgConfigHome, "opencode.json"),
      join(xdgConfigHome, "opencode.jsonc"),
      join(xdgConfigHome, "opencode", "opencode.json"),
      join(xdgConfigHome, "opencode", "opencode.jsonc"),
    ],
  });
  const modelSettingsStore = suppliedModelSettingsStore ?? new OpenCodeModelSettingsStore({
    path: modelSettingsPath ?? join(dirname(resolve(stateRoot)), "opencode-model-settings.json"),
  });
  // Resolve immediately before every `opencode run`.  This deliberately keeps
  // a task that has not started (including a retry/recovery) aligned with the
  // current workbench setting, while a process already running is untouched.
  runner.setModelResolver(async () => (await modelSettingsStore.get()).model);
  // Tasks that were already queued when the workbench restarted still contain
  // their last persisted display value. Serialize refreshes so an initial
  // refresh cannot overwrite a newer settings-save refresh.
  let queuedModelSync = Promise.resolve();
  function syncQueuedAuditModels() {
    const operation = queuedModelSync.catch(() => {}).then(async () => {
      await Promise.all([runner.ready, modelSettingsStore.ready]);
      const settings = await modelSettingsStore.get();
      return runner.syncQueuedAuditModels(settings.model);
    });
    queuedModelSync = operation;
    return operation;
  }
  const initialQueuedModelSync = syncQueuedAuditModels();
  const dynamicRunner = suppliedDynamicRunner ?? new DynamicValidationRunner({
    stateRoot: dynamicStateRoot ?? join(dirname(stateRoot), "dynamic-validation-runs"),
    enabled: dynamicRunnerEnabled,
    registryPath: DEFAULT_STAGE_REGISTRY,
    rolesPath: DEFAULT_ROLES,
  });
  const environmentService = suppliedEnvironmentService ?? new EnvironmentHealthService({
    projectRoot: PROJECT_ROOT,
    configPaths: [resolve(platformConfigPath)],
  });
  const findingWorkflow = suppliedFindingWorkflow ?? new FindingWorkflowStore({
    stateRoot: findingStateRoot ?? join(dirname(stateRoot), "finding-workflow"),
  });
  const requestHistory = suppliedRequestHistoryStore ?? new RequestHistoryStore({
    stateRoot: requestStateRoot ?? join(dirname(resolve(stateRoot)), "dynamic-request-workbench"),
  });

  function runtimeSources() {
    const artifacts = new Map(runner.artifactSources().map(source => [source.repository_id, source.reports_root]));
    return runner.runtimeRepositories().map(repository => ({ repository, root: legacyRuntimeRoot ? resolvedRuntimeRoot : join(artifacts.get(repository.id), "validation-handoff", "runtime") }));
  }

  async function validationRequests() {
    const values = [];
    for (const { repository, root } of runtimeSources()) {
      const reportsRoot = runner.artifactSources().find(source => source.repository_id === repository.id)?.reports_root;
      if (reportsRoot) {
        for (const audit of runner.listAudits().filter(item => item.repository_id === repository.id && item.status === "completed")) {
          await materializeManualValidationRequests({ reportsRoot, auditId: audit.id, repositoryId: repository.id, commit: audit.commit });
        }
      }
      for (const request of await listValidationRequests(root)) values.push({
        ...request,
        job_id: scopedResourceId(repository.id, request.id),
        repository_id: repository.id,
        repository_name: repository.name,
      });
    }
    const jobs = new Map(dynamicRunner.listRuns().map(run => [run.id, run]));
    return Promise.all(values.map(async request => {
      const legacyJob = jobs.get(request.id);
      const audit = runner.getAudit(request.audit_id);
      const auditManaged = Boolean(audit && audit.repository_id === request.repository_id);
      const policy = await runner.dynamicValidationPolicy(request.audit_id, request.repository_id);
      const blockerMessages = {
        "request-invalid": "动态验证请求未通过摘要或字段校验。",
        "validation-type-unsupported": "该漏洞类型不属于当前 Web 动态验证范围。",
        "validation-result-exists": "该漏洞已有动态验证结果，默认拒绝覆盖。",
      };
      return {
        ...request,
        artifact_dispatch_ready: request.dispatch_ready,
        audit_managed: auditManaged,
        task_test_environment_preconfigured: policy.enabled,
        dispatch_ready: request.dispatch_ready && auditManaged,
        dispatch_blocked_reason: !auditManaged
          ? "动态验证请求不属于当前工作台受管审计。"
          : request.dispatch_ready ? null : request.dispatch_blockers.map(code => blockerMessages[code] ?? code).join(" "),
        job: jobs.get(request.job_id) ?? (legacyJob?.repository_id === request.repository_id ? legacyJob : null),
      };
    }));
  }

  async function validationRuns() {
    const values = [];
    for (const { repository, root } of runtimeSources()) {
      for (const run of await listValidationRuns(root)) values.push({
        ...run,
        resource_id: scopedResourceId(repository.id, run.id),
        repository_id: repository.id,
        repository_name: repository.name,
      });
    }
    return values.sort((a, b) => String(b.recorded_at ?? "").localeCompare(String(a.recorded_at ?? "")));
  }

  async function httpExchanges() {
    const records = new Map((await requestHistory.list({ limit: 500 })).map(exchange => [exchange.exchange_id, exchange]));
    for (const { repository, root } of runtimeSources()) {
      for (const run of await listValidationRunDetails(root)) {
        for (const exchange of run.network?.exchanges ?? []) records.set(exchange.exchange_id, {
          ...exchange,
          audit_id: run.audit_id,
          finding_id: run.finding?.id ?? null,
          repository_id: repository.id,
          repository_name: repository.name,
        });
      }
    }
    return [...records.values()].sort((left, right) => String(right.started_at ?? "").localeCompare(String(left.started_at ?? "")));
  }

  async function httpExchange(exchangeId) {
    return (await httpExchanges()).find(exchange => exchange.exchange_id === exchangeId) ?? null;
  }

  async function validationRun(resourceId) {
    for (const { repository, root } of runtimeSources()) {
      for (const run of await listValidationRunDetails(root)) {
        const scopedId = scopedResourceId(repository.id, run.id);
        if (resourceId === scopedId || resourceId === run.id) return {
          ...run,
          resource_id: scopedId,
          repository_id: repository.id,
          repository_name: repository.name,
        };
      }
    }
    return null;
  }

  async function modelSettingsSnapshot() {
    const [catalog, settings] = await Promise.all([modelCatalog.snapshot(), modelSettingsStore.get()]);
    const selected = settings.model ?? DEFAULT_MODEL_SELECTION;
    return {
      selected_model: selected,
      options: [
        { value: DEFAULT_MODEL_SELECTION, label: "默认" },
        ...catalog.models.map(model => ({ value: model, label: model })),
      ],
      sources: catalog.sources,
      selection_available: selected === DEFAULT_MODEL_SELECTION || catalog.models.includes(selected),
      updated_at: settings.updated_at,
    };
  }

  // The UI used to request /workspace and /repositories together.  Both build a
  // complete artifact snapshot, so a single browser refresh could recursively
  // scan the same reports twice.  Share only concurrent work (rather than a
  // time-based cache) to keep mutations immediately observable.
  let snapshotInFlight = null;
  async function snapshot() {
    if (snapshotInFlight) return snapshotInFlight;
    const operation = (async () => {
      await Promise.all([runner.ready, findingWorkflow.ready, queueScheduler.ready, modelSettingsStore.ready, initialQueuedModelSync]);
      await runner.reconcileTerminalCompletions("workspace-watchdog");
      const runnerAudits = await runner.listAuditsWithTodo();
      const validationByRepository = new Map();
      await Promise.all(runtimeSources().map(async ({ repository, root }) => {
        validationByRepository.set(repository.id, await listValidationRuns(root));
      }));
      const sources = runner.artifactSources();
      const snapshots = [];
      for (const source of sources) {
        const sourceRuns = runnerAudits.filter(audit => audit.repository_id === source.repository_id);
        const value = await buildWorkspaceSnapshot({ reportsRoot: source.reports_root, validationRuns: validationByRepository.get(source.repository_id) ?? [], runnerAudits: sourceRuns });
        value.audits = value.audits.map(audit => ({
          ...audit,
          repository_id: audit.repository_id ?? source.repository_id,
          repository_name: audit.repository_name ?? source.repository_name,
        }));
        value.findings = value.findings.map(finding => {
          const resourceId = scopedResourceId(source.repository_id, `${finding.audit_id}\0${finding.id}`);
          return { ...finding, resource_id: resourceId, repository_id: source.repository_id, repository_name: source.repository_name, workflow: findingWorkflow.get(resourceId) };
        });
        value.reports = value.reports.map(report => ({
          ...report,
          id: scopedResourceId(source.repository_id, report.id),
          repository_id: source.repository_id,
          repository_name: source.repository_name,
        }));
        value.artifacts = value.artifacts.map(artifact => ({
          ...artifact,
          id: scopedResourceId(source.repository_id, artifact.id),
          repository_id: source.repository_id,
        }));
        snapshots.push(value);
      }
      const merged = mergeSnapshots(snapshots);
      merged.queue = await queueScheduler.snapshot();
      return merged;
    })();
    snapshotInFlight = operation;
    try {
      return await operation;
    } finally {
      if (snapshotInFlight === operation) snapshotInFlight = null;
    }
  }

  async function reportContent(reportId) {
    const data = await snapshot();
    const report = data.reports.find(item => item.id === reportId);
    if (!report) throw Object.assign(new Error("没有找到最终报告。"), { statusCode: 404, code: "report-not-found" });
    const source = runner.artifactSources().find(item => item.repository_id === report.repository_id);
    if (!source) throw Object.assign(new Error("报告所属仓库不再可用。"), { statusCode: 409, code: "report-source-unavailable" });
    const [root, candidate] = await Promise.all([
      realpath(source.reports_root),
      realpath(resolve(source.reports_root, report.path)),
    ]);
    if (!isWithin(root, candidate)) throw Object.assign(new Error("报告路径越出受控制品目录。"), { statusCode: 409, code: "report-path-invalid" });
    const info = await stat(candidate);
    if (!info.isFile() || info.size > MAX_REPORT_BODY) throw Object.assign(new Error("报告文件不可读取或超过大小限制。"), { statusCode: 413, code: "report-body-too-large" });
    const bytes = await readFile(candidate);
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (!report.sha256 || digest !== report.sha256) throw Object.assign(new Error("报告内容与记录摘要不一致，请刷新制品后重试。"), { statusCode: 409, code: "report-digest-mismatch" });
    return { report, bytes, digest };
  }

  async function repositoriesSnapshot() {
    const [items, data] = await Promise.all([runner.listRepositories(), snapshot()]);
    return items.map(repository => {
      const audits = data.audits
        .filter(audit => audit.repository_id === repository.id)
        .sort((a, b) => String(b.updated_at ?? b.created_at ?? "").localeCompare(String(a.updated_at ?? a.created_at ?? "")));
      return {
        ...repository,
        audit_count: audits.length,
        active_audit_count: audits.filter(audit => ["queued", "preparing", "recovering", "running", "pausing", "paused", "cancelling"].includes(audit.status)).length,
        last_audit_at: audits[0]?.updated_at ?? audits[0]?.created_at ?? null,
        last_audit_status: audits[0]?.status ?? null,
      };
    });
  }

  const server = createHttpServer(async (request, response) => {
    securityHeaders(response);
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (request.method === "GET" && (url.pathname === "/api/health" || url.pathname === "/api/v1/runtime/health")) {
        json(response, 200, { ok: true, service: "opencode-audit-workbench", runner: runner.health(), dynamic_runner: dynamicRunner.health(), request_history: { mode: "read_only" } });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/environment") {
        json(response, 200, await environmentService.snapshot({ force: url.searchParams.get("refresh") === "1" }));
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/dashboard/summary") {
        const data = await snapshot();
        json(response, 200, { ...data.summary, generated_at: data.generated_at });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/settings/queue") {
        json(response, 200, { queue: await queueScheduler.snapshot() });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/settings/model") {
        json(response, 200, { model: await modelSettingsSnapshot() });
        return;
      }
      if (request.method === "PUT" && url.pathname === "/api/v1/settings/model") {
        assertSafeMutation(request);
        const body = await requestJson(request);
        const catalog = await modelCatalog.snapshot();
        await modelSettingsStore.update(body.model, catalog.models);
        await syncQueuedAuditModels();
        json(response, 200, { model: await modelSettingsSnapshot() });
        return;
      }
      if (request.method === "PUT" && url.pathname === "/api/v1/settings/queue") {
        assertSafeMutation(request);
        json(response, 200, { queue: await queueScheduler.updateSettings(await requestJson(request)) });
        return;
      }
      if (request.method === "POST" && (url.pathname === "/api/v1/settings/queue/activate" || url.pathname === "/api/v1/settings/queue/deactivate")) {
        assertSafeMutation(request);
        await requestJson(request);
        const queue = url.pathname.endsWith("/activate") ? await queueScheduler.activate() : await queueScheduler.deactivate();
        json(response, 200, { queue });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/v1/settings/queue/dispatch") {
        assertSafeMutation(request);
        await requestJson(request);
        await queueScheduler.triggerNow();
        json(response, 202, { queue: await queueScheduler.snapshot() });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/workspace") {
        const { findings: _findings, ...workspace } = await snapshot();
        json(response, 200, workspace);
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/repositories") {
        const items = await repositoriesSnapshot();
        json(response, 200, { items, count: items.length });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/v1/repositories") {
        assertSafeMutation(request);
        const repository = await runner.addRepository(await requestJson(request), request.headers["idempotency-key"]);
        json(response, 201, repository, { Location: `/api/v1/repositories/${encodeURIComponent(repository.id)}` });
        return;
      }
      const repositoryDelete = url.pathname.match(/^\/api\/v1\/repositories\/([^/]+)$/);
      if (request.method === "DELETE" && repositoryDelete) {
        assertSafeMutation(request);
        const repositoryId = decodeURIComponent(repositoryDelete[1]);
        const body = await requestJson(request);
        if (body.confirmation !== repositoryId) throw Object.assign(new Error("删除确认必须与项目 ID 完全一致。"), { statusCode: 422, code: "repository-delete-confirmation-invalid" });
        const repository = (await repositoriesSnapshot()).find(item => item.id === repositoryId);
        if (!repository) throw Object.assign(new Error("审计项目不存在。"), { statusCode: 404, code: "repository-not-found" });
        if ((repository.audit_count ?? 0) > 0) throw Object.assign(new Error("该项目仍有关联审计；请先删除这些审计任务。"), { statusCode: 409, code: "repository-has-audits" });
        json(response, 200, await runner.removeRepository(repositoryId));
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/audits") {
        const data = await snapshot();
        json(response, 200, { items: data.audits, count: data.audits.length });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/v1/audits") {
        assertSafeMutation(request);
        const [input, settings] = await Promise.all([requestJson(request), modelSettingsStore.get()]);
        // The selected value is server-owned: a browser cannot inject arbitrary
        // flags into the OpenCode command by posting its own `model` field.
        // The runner resolves it again when the queued task actually launches.
        const audit = await runner.createAudit({ ...input, model: settings.model }, request.headers["idempotency-key"]);
        json(response, 202, audit, { Location: `/api/v1/audits/${encodeURIComponent(audit.id)}`, ETag: `"${audit.version}"` });
        return;
      }
      const auditId = matchAuditPath(url.pathname);
      if (request.method === "DELETE" && auditId) {
        assertSafeMutation(request);
        const body = await requestJson(request);
        if (body.confirmation !== auditId) throw Object.assign(new Error("删除确认必须与 audit_id 完全一致。"), { statusCode: 422, code: "audit-delete-confirmation-invalid" });
        const data = await snapshot();
        const audit = data.audits.find(item => item.id === auditId);
        if (!audit) throw Object.assign(new Error("审计不存在。"), { statusCode: 404, code: "audit-not-found" });
        const expected = String(request.headers["if-match"] ?? "").replaceAll('"', "");
        if (Number(expected) !== audit.version) throw Object.assign(new Error("审计版本已变化，请刷新后重试。"), { statusCode: 412, code: "version-mismatch" });
        const runnerAudit = runner.getAudit(auditId);
        if (runnerAudit && ["preparing", "recovering", "running", "pausing", "paused", "cancelling"].includes(runnerAudit.status)) {
          throw Object.assign(new Error("运行中的审计不能删除；请先取消并等待任务结束。"), { statusCode: 409, code: "audit-delete-active" });
        }
        const activeValidations = dynamicRunner.listRuns().filter(run => run.audit_id === auditId && ["preparing", "running", "cancelling"].includes(run.status));
        if (activeValidations.length) throw Object.assign(new Error("该审计仍有动态验证正在运行；请先取消并等待验证结束。"), { statusCode: 409, code: "audit-validation-active" });
        const artifacts = data.artifacts.filter(artifact => artifact.audit_id === auditId && artifact.repository_id === audit.repository_id);
        const validationRunsRemoved = await dynamicRunner.deleteAuditRuns(auditId);
        const findingWorkflowsRemoved = await findingWorkflow.deleteAudit(auditId, audit.repository_id);
        const result = await runner.deleteAudit(auditId, {
          repositoryId: audit.repository_id,
          expectedVersion: expected,
          artifactPaths: artifacts.map(artifact => artifact.path),
        });
        json(response, 200, {
          ...result,
          removed_validation_runs: validationRunsRemoved,
          removed_finding_workflows: findingWorkflowsRemoved,
        });
        return;
      }
      if (request.method === "GET" && auditId) {
        const data = await snapshot();
        const audit = data.audits.find(item => item.id === auditId);
        if (!audit) json(response, 404, { error: "audit-not-found" });
        else json(response, 200, audit, { ETag: `"${audit.version}"` });
        return;
      }
      const actionAuditId = matchAuditPath(url.pathname, "actions");
      if (request.method === "POST" && actionAuditId) {
        assertSafeMutation(request);
        const body = await requestJson(request);
        const expected = String(request.headers["if-match"] ?? "").replaceAll('"', "");
        let audit;
        if (body.action === "dispatch") {
          const current = runner.getAudit(actionAuditId);
          if (!current) throw Object.assign(new Error("审计不存在。"), { statusCode: 404, code: "audit-not-found" });
          if (Number(expected) !== current.version) {
            throw Object.assign(new Error("审计版本已变化，请刷新后重试。"), { statusCode: 412, code: "version-mismatch" });
          }
          audit = await queueScheduler.dispatchAuditNow(actionAuditId);
        } else {
          audit = await runner.action(actionAuditId, body.action, expected, request.headers["idempotency-key"]);
        }
        json(response, 202, audit, { ETag: `"${audit.version}"` });
        return;
      }
      const eventAuditId = matchAuditPath(url.pathname, "events");
      if (request.method === "GET" && eventAuditId) {
        await streamAuditEvents(request, response, runner, eventAuditId);
        return;
      }
      const logAuditId = matchAuditPath(url.pathname, "logs");
      if (request.method === "GET" && logAuditId) {
        const items = runner.getAudit(logAuditId) ? await runner.recentLogs(logAuditId, url.searchParams.get("limit")) : [];
        json(response, 200, { items, count: items.length });
        return;
      }
      const terminalAuditId = matchAuditPath(url.pathname, "terminal");
      if (request.method === "GET" && terminalAuditId) {
        json(response, 200, await runner.terminalSnapshot(terminalAuditId));
        return;
      }
      const terminalResizeAuditId = matchAuditPath(url.pathname, "terminal/resize");
      if (request.method === "POST" && terminalResizeAuditId) {
        assertSafeMutation(request);
        const body = await requestJson(request);
        json(response, 200, await runner.resizeTerminal(terminalResizeAuditId, body.columns, body.rows));
        return;
      }
      const artifactAuditId = matchAuditPath(url.pathname, "artifacts");
      if (request.method === "GET" && artifactAuditId) {
        const data = await snapshot();
        const items = data.artifacts.filter(artifact => artifact.audit_id === artifactAuditId);
        json(response, 200, { items, count: items.length });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/findings") {
        const data = await snapshot();
        json(response, 200, paginateFindings(data.findings, url));
        return;
      }
      const findingWorkflowId = matchFindingWorkflowPath(url.pathname);
      if (request.method === "POST" && findingWorkflowId) {
        assertSafeMutation(request);
        const data = await snapshot();
        const finding = data.findings.find(item => item.resource_id === findingWorkflowId);
        if (!finding) throw Object.assign(new Error("没有找到对应漏洞。"), { statusCode: 404, code: "finding-not-found" });
        const body = await requestJson(request);
        const expected = String(request.headers["if-match"] ?? "0").replaceAll('"', "");
        const workflow = await findingWorkflow.update({
          finding,
          status: body.status,
          note: body.note ?? "",
          expectedVersion: expected,
          idempotencyKey: request.headers["idempotency-key"],
        });
        json(response, 200, workflow, { ETag: `"${workflow.version}"` });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/reports") {
        const data = await snapshot();
        json(response, 200, { items: data.reports, count: data.reports.length });
        return;
      }
      const reportDownloadId = matchReportPath(url.pathname, "download");
      if (request.method === "GET" && reportDownloadId) {
        const { report, bytes, digest } = await reportContent(reportDownloadId);
        const fileName = `security-audit-report.${String(report.audit_id).replaceAll(/[^A-Za-z0-9._-]/g, "-")}.md`;
        response.writeHead(200, {
          "Content-Type": "text/markdown; charset=utf-8",
          "Content-Length": bytes.length,
          "Content-Disposition": `attachment; filename="${fileName}"`,
          "Cache-Control": "no-store",
          ETag: `"sha256-${digest}"`,
        });
        response.end(bytes);
        return;
      }
      const reportId = matchReportPath(url.pathname);
      if (request.method === "GET" && reportId) {
        const { report, bytes } = await reportContent(reportId);
        const body = bytes.toString("utf8");
        json(response, 200, { ...report, body, rendered_html: markdownRenderer.render(body), rendering: "markdown-it-html-disabled" });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/validation-requests") {
        const items = await validationRequests();
        json(response, 200, { items, count: items.length });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/http-exchanges") {
        const limit = Math.max(1, Math.min(Number(url.searchParams.get("limit")) || 100, 500));
        const items = (await httpExchanges()).slice(0, limit);
        json(response, 200, { items, count: items.length });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/v1/http-exchanges/export/bruno") {
        assertSafeMutation(request);
        const body = await requestJson(request);
        if (!Array.isArray(body.exchange_ids) || body.exchange_ids.length < 1 || body.exchange_ids.length > 100) {
          throw Object.assign(new Error("Bruno 导出必须选择 1-100 条记录。"), { statusCode: 422, code: "bruno-export-selection-invalid" });
        }
        const ids = [...new Set(body.exchange_ids.map(value => String(value)))];
        if (ids.some(id => !/^http_[A-Za-z0-9-]+$/.test(id))) {
          throw Object.assign(new Error("Bruno 导出的 exchange ID 无效。"), { statusCode: 422, code: "bruno-export-id-invalid" });
        }
        const available = new Map((await httpExchanges()).map(exchange => [exchange.exchange_id, exchange]));
        const exchanges = ids.map(id => available.get(id) ?? null);
        const missingIndex = exchanges.findIndex(value => !value);
        if (missingIndex >= 0) {
          throw Object.assign(new Error(`没有找到 HTTP exchange：${ids[missingIndex]}`), { statusCode: 404, code: "exchange-not-found" });
        }
        const archive = buildOpenCollectionArchive(exchanges);
        binary(response, 200, archive.bytes, "application/zip", archive.filename);
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/v1/http-exchanges/export/har") {
        assertSafeMutation(request);
        const body = await requestJson(request);
        if (!Array.isArray(body.exchange_ids) || body.exchange_ids.length < 1 || body.exchange_ids.length > 100) {
          throw Object.assign(new Error("HAR 导出必须选择 1-100 条记录。"), { statusCode: 422, code: "har-export-selection-invalid" });
        }
        const ids = [...new Set(body.exchange_ids.map(value => String(value)))];
        if (ids.some(id => !/^http_[A-Za-z0-9-]+$/.test(id))) throw Object.assign(new Error("HAR 导出的 exchange ID 无效。"), { statusCode: 422, code: "har-export-id-invalid" });
        const available = new Map((await httpExchanges()).map(exchange => [exchange.exchange_id, exchange]));
        const exchanges = ids.map(id => available.get(id) ?? null);
        const missingIndex = exchanges.findIndex(value => !value);
        if (missingIndex >= 0) throw Object.assign(new Error(`没有找到 HTTP exchange：${ids[missingIndex]}`), { statusCode: 404, code: "exchange-not-found" });
        const archive = buildHar(exchanges);
        binary(response, 200, archive.bytes, "application/json", archive.filename);
        return;
      }
      const exchangeDetail = url.pathname.match(/^\/api\/v1\/http-exchanges\/([^/]+)$/);
      if (request.method === "GET" && exchangeDetail) {
        const value = await httpExchange(decodeURIComponent(exchangeDetail[1]));
        if (!value) json(response, 404, { error: "exchange-not-found" });
        else json(response, 200, { exchange: value });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/v1/validations") {
        assertSafeMutation(request);
        const input = await requestJson(request);
        const repository = runner.runtimeRepositories().find(item => item.id === input.repository_id);
        if (!repository) throw Object.assign(new Error("仓库不在服务端白名单中。"), { statusCode: 422, code: "repository-not-allowed" });
        const requests = await validationRequests();
        const descriptor = requests.find(item => item.id === input.validation_request_id && item.repository_id === repository.id);
        if (!descriptor) throw Object.assign(new Error("没有找到动态验证请求。"), { statusCode: 404, code: "validation-request-not-found" });
        if (!descriptor.artifact_dispatch_ready) throw Object.assign(new Error("没有找到可调度的密封动态验证请求。"), { statusCode: 422, code: "validation-request-not-ready" });
        const source = runner.artifactSources().find(item => item.repository_id === repository.id);
        const root = runtimeSources().find(item => item.repository.id === repository.id)?.root;
        const executionPaths = await runner.ensureExecutionWorkspace(descriptor.audit_id, repository.id);
        const audit = runner.getAudit(descriptor.audit_id);
        const run = await dynamicRunner.create({
          input,
          repository,
          reportsRoot: source.reports_root,
          runtimeRoot: root,
          executionPaths,
          requestDescriptor: { ...descriptor, request_id: descriptor.id, id: descriptor.job_id, model: audit?.model ?? null },
          idempotencyKey: request.headers["idempotency-key"],
        });
        json(response, 202, run, { Location: `/api/v1/validations/${encodeURIComponent(run.id)}`, ETag: `"${run.version}"` });
        return;
      }
      const validationAction = url.pathname.match(/^\/api\/v1\/validations\/([^/]+)\/actions$/);
      if (request.method === "POST" && validationAction) {
        assertSafeMutation(request);
        const body = await requestJson(request);
        if (body.action !== "cancel") throw Object.assign(new Error("动态验证当前只支持取消操作。"), { statusCode: 409, code: "validation-action-not-allowed" });
        json(response, 202, await dynamicRunner.cancel(decodeURIComponent(validationAction[1])));
        return;
      }
      const validationEvents = url.pathname.match(/^\/api\/v1\/validations\/([^/]+)\/events$/);
      if (request.method === "GET" && validationEvents) {
        await streamValidationEvents(request, response, dynamicRunner, decodeURIComponent(validationEvents[1]));
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/runs") {
        const runs = await validationRuns();
        json(response, 200, { runs, count: runs.length });
        return;
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/runs/")) {
        const id = decodeURIComponent(url.pathname.slice("/api/runs/".length));
        const run = await validationRun(id);
        if (!run) json(response, 404, { error: "run-not-found" });
        else json(response, 200, { run });
        return;
      }
      if (request.method === "GET" && await staticResponse(response, url.pathname)) return;
      if (request.method !== "GET") json(response, 405, { error: "method-not-allowed" });
      else json(response, 404, { error: "not-found" });
    } catch (error) {
      json(response, error.statusCode ?? 500, { error: error.code ?? "internal-error", message: error.message });
    }
  });
  server.shutdownRunners = async () => {
    await queueScheduler.shutdown();
    await Promise.all([runner.shutdown(), dynamicRunner.shutdown()]);
  };
  return server;
}

export function createValidationObservatoryServer(options = {}) {
  return createAuditWorkbenchServer({
    ...options,
    repositories: options.repositories ?? [{ id: "workspace", name: "OpenCode Multi Agents", path: PROJECT_ROOT }],
    legacyRuntimeRoot: options.legacyRuntimeRoot ?? options.repositories === undefined,
  });
}

export function parseArgs(argv) {
  const options = {
    host: process.env.AUDIT_WORKBENCH_HOST ?? process.env.DYNAMIC_VALIDATION_WEB_HOST ?? "127.0.0.1",
    port: Number(process.env.AUDIT_WORKBENCH_PORT ?? process.env.DYNAMIC_VALIDATION_WEB_PORT ?? 4173),
    runtimeRoot: process.env.DYNAMIC_VALIDATION_RUNTIME_ROOT ?? DEFAULT_RUNTIME_ROOT,
    stateRoot: process.env.AUDIT_WORKBENCH_STATE_ROOT ?? DEFAULT_STATE_ROOT,
    runnerEnabled: false,
    dynamicRunnerEnabled: false,
    repositories: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === "--host") options.host = argv[++index];
    else if (option === "--port") options.port = Number(argv[++index]);
    else if (option === "--runtime-root") options.runtimeRoot = argv[++index];
    else if (option === "--state-root") options.stateRoot = argv[++index];
    else if (option === "--enable-runner") options.runnerEnabled = true;
    else if (option === "--enable-dynamic-validation") options.dynamicRunnerEnabled = true;
    else if (option === "--repo") {
      const value = argv[++index] ?? "";
      const separator = value.indexOf("=");
      if (separator < 1) throw new Error("--repo 必须使用 id=/absolute/path 格式");
      const path = value.slice(separator + 1);
      if (!isAbsolute(path)) throw new Error("--repo 必须使用 id=/absolute/path 格式");
      options.repositories.push({ id: value.slice(0, separator), path });
    } else throw new Error(`Unknown argument: ${option}`);
  }
  if (!BIND_HOSTS.has(options.host)) throw new Error("工作台只支持 localhost、loopback 地址或 0.0.0.0 监听");
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65535) throw new Error("Invalid port");
  return options;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArgs(process.argv.slice(2));
    const server = createAuditWorkbenchServer(options);
    server.listen(options.port, options.host, () => {
      const address = server.address();
      const host = options.host === "::1" || options.host === "[::1]" ? `[${options.host.replaceAll("[", "").replaceAll("]", "")}]` : options.host;
      const modes = [options.runnerEnabled ? "静态审计 Runner 已启用" : "静态只读", options.dynamicRunnerEnabled ? "动态验证 Runner 已启用" : "动态验证只读"];
      process.stdout.write(`OpenCode 审计工作台已启动：http://${host}:${address.port}（${modes.join("；")}）\n`);
    });
    let shuttingDown = false;
    const shutdown = async signal => {
      if (shuttingDown) return;
      shuttingDown = true;
      process.stdout.write(`收到 ${signal}，正在停止工作台创建的 OpenCode 子进程…\n`);
      await server.shutdownRunners();
      server.close(() => { process.exitCode = 0; });
    };
    process.once("SIGINT", () => shutdown("SIGINT").catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }));
    process.once("SIGTERM", () => shutdown("SIGTERM").catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
