#!/usr/bin/env node

import { createServer as createHttpServer } from "node:http";
import { createHash } from "node:crypto";
import { readFile, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { AuditRunner } from "./audit-runner.mjs";
import { getValidationRun, listValidationRequests, listValidationRuns } from "./model.mjs";
import { buildWorkspaceSnapshot } from "./workspace-model.mjs";
import { DynamicValidationRunner } from "./validation-runner.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(HERE, "../../..");
const PUBLIC_ROOT = join(HERE, "public");
const DEFAULT_RUNTIME_ROOT = join(PROJECT_ROOT, "reports", "validation-handoff", "runtime");
const DEFAULT_STATE_ROOT = join(PROJECT_ROOT, "reports", "platform", "audit-runs");
const DEFAULT_STAGE_REGISTRY = join(PROJECT_ROOT, ".opencode", "skills", "common-subagent", "audit-artifact-management", "contracts", "stage-agent-contracts.json");
const DEFAULT_ROLES = join(PROJECT_ROOT, ".opencode", "agent-manifest", "roles.json");
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const MAX_REQUEST_BODY = 64 * 1024;
const MAX_REPORT_BODY = 8 * 1024 * 1024;
const STATIC_FILES = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/index.html", ["index.html", "text/html; charset=utf-8"]],
  ["/app.js", ["app.js", "text/javascript; charset=utf-8"]],
  ["/styles.css", ["styles.css", "text/css; charset=utf-8"]],
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
    if (query && !`${finding.id} ${finding.title} ${finding.location.path ?? ""}`.toLowerCase().includes(query)) return false;
    return true;
  });
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
  merged.summary.active_audits = merged.audits.filter(audit => ["queued", "preparing", "running", "pausing", "paused", "cancelling"].includes(audit.status)).length;
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
  repositories = [{ id: "workspace", name: "OpenCode Multi Agents", path: PROJECT_ROOT }],
  runnerEnabled = false,
  runner: suppliedRunner = null,
  dynamicRunnerEnabled = false,
  dynamicStateRoot = null,
  dynamicRunner: suppliedDynamicRunner = null,
} = {}) {
  const resolvedRuntimeRoot = resolve(runtimeRoot);
  const runner = suppliedRunner ?? new AuditRunner({ stateRoot, repositories, enabled: runnerEnabled });
  const dynamicRunner = suppliedDynamicRunner ?? new DynamicValidationRunner({
    stateRoot: dynamicStateRoot ?? join(dirname(stateRoot), "dynamic-validation-runs"),
    enabled: dynamicRunnerEnabled,
    registryPath: DEFAULT_STAGE_REGISTRY,
    rolesPath: DEFAULT_ROLES,
  });

  async function validationRequests() {
    const values = [];
    const repositories = runner.runtimeRepositories();
    for (let index = 0; index < repositories.length; index += 1) {
      const repository = repositories[index];
      const root = index === 0 ? resolvedRuntimeRoot : join(repository.path, "reports", "validation-handoff", "runtime");
      for (const request of await listValidationRequests(root)) values.push({ ...request, repository_id: repository.id, repository_name: repository.name });
    }
    const jobs = new Map(dynamicRunner.listRuns().map(run => [run.id, run]));
    return values.map(request => ({ ...request, job: jobs.get(request.id) ?? null }));
  }

  async function snapshot() {
    await runner.ready;
    const [validationRuns, runnerAudits] = await Promise.all([listValidationRuns(resolvedRuntimeRoot), Promise.resolve(runner.listAudits())]);
    const sources = runner.artifactSources();
    const snapshots = [];
    for (let sourceIndex = 0; sourceIndex < sources.length; sourceIndex += 1) {
      const source = sources[sourceIndex];
      const sourceRuns = runnerAudits.filter(audit => audit.repository_id === source.repository_id);
      const value = await buildWorkspaceSnapshot({ reportsRoot: source.reports_root, validationRuns: sourceIndex === 0 ? validationRuns : [], runnerAudits: sourceRuns });
      value.audits = value.audits.map(audit => ({
        ...audit,
        repository_id: audit.repository_id ?? source.repository_id,
        repository_name: audit.repository_name ?? source.repository_name,
      }));
      value.findings = value.findings.map(finding => ({ ...finding, repository_id: source.repository_id, repository_name: source.repository_name }));
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
    return mergeSnapshots(snapshots);
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

  const server = createHttpServer(async (request, response) => {
    securityHeaders(response);
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (request.method === "GET" && (url.pathname === "/api/health" || url.pathname === "/api/v1/runtime/health")) {
        json(response, 200, { ok: true, service: "opencode-audit-workbench", runner: runner.health(), dynamic_runner: dynamicRunner.health() });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/dashboard/summary") {
        const data = await snapshot();
        json(response, 200, { ...data.summary, generated_at: data.generated_at });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/workspace") {
        json(response, 200, await snapshot());
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/repositories") {
        const items = await runner.listRepositories();
        json(response, 200, { items, count: items.length });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/audits") {
        const data = await snapshot();
        json(response, 200, { items: data.audits, count: data.audits.length });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/v1/audits") {
        assertSafeMutation(request);
        const audit = await runner.createAudit(await requestJson(request), request.headers["idempotency-key"]);
        json(response, 202, audit, { Location: `/api/v1/audits/${encodeURIComponent(audit.id)}`, ETag: `"${audit.version}"` });
        return;
      }
      const auditId = matchAuditPath(url.pathname);
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
        const audit = await runner.action(actionAuditId, body.action, expected, request.headers["idempotency-key"]);
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
      const artifactAuditId = matchAuditPath(url.pathname, "artifacts");
      if (request.method === "GET" && artifactAuditId) {
        const data = await snapshot();
        const items = data.artifacts.filter(artifact => artifact.audit_id === artifactAuditId);
        json(response, 200, { items, count: items.length });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/findings") {
        const data = await snapshot();
        const items = filterFindings(data.findings, url);
        json(response, 200, { items, count: items.length });
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
        json(response, 200, { ...report, body: bytes.toString("utf8") });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/v1/validation-requests") {
        const items = await validationRequests();
        json(response, 200, { items, count: items.length });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/v1/validations") {
        assertSafeMutation(request);
        const input = await requestJson(request);
        const repository = runner.runtimeRepositories().find(item => item.id === input.repository_id);
        if (!repository) throw Object.assign(new Error("仓库不在服务端白名单中。"), { statusCode: 422, code: "repository-not-allowed" });
        const requests = await validationRequests();
        const descriptor = requests.find(item => item.id === input.validation_request_id && item.repository_id === repository.id);
        if (!descriptor?.dispatch_ready) throw Object.assign(new Error("没有找到可调度的密封动态验证请求。"), { statusCode: 422, code: "validation-request-not-ready" });
        const repositories = runner.runtimeRepositories();
        const repositoryIndex = repositories.findIndex(item => item.id === repository.id);
        const root = repositoryIndex === 0 ? resolvedRuntimeRoot : join(repository.path, "reports", "validation-handoff", "runtime");
        const run = await dynamicRunner.create({ input, repository, runtimeRoot: root, requestDescriptor: descriptor, idempotencyKey: request.headers["idempotency-key"] });
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
        const runs = await listValidationRuns(resolvedRuntimeRoot);
        json(response, 200, { runs, count: runs.length });
        return;
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/runs/")) {
        const id = decodeURIComponent(url.pathname.slice("/api/runs/".length));
        const run = await getValidationRun(resolvedRuntimeRoot, id);
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
  server.shutdownRunners = () => Promise.all([runner.shutdown(), dynamicRunner.shutdown()]);
  return server;
}

export const createValidationObservatoryServer = createAuditWorkbenchServer;

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
      options.repositories.push({ id: value.slice(0, separator), path: value.slice(separator + 1) });
    } else throw new Error(`Unknown argument: ${option}`);
  }
  if (!LOOPBACK_HOSTS.has(options.host)) throw new Error("工作台只能监听 loopback 地址");
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65535) throw new Error("Invalid port");
  if (options.repositories.length === 0) options.repositories.push({ id: "workspace", name: "OpenCode Multi Agents", path: PROJECT_ROOT });
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
