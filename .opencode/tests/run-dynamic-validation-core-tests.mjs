#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { strFromU8, unzipSync } from "fflate";
import { parse } from "yaml";
import {
  authorizeDynamicTask,
  BrowserSessionBroker,
  chooseBrowserMode,
  chromeDevtoolsMcpDefinition,
  sharedChromeReadiness,
} from "../web/dynamic-validation-observatory/dynamic-validation-core.mjs";
import { RequestHistoryStore } from "../web/dynamic-validation-observatory/request-history-store.mjs";
import { buildOpenCollectionArchive } from "../web/dynamic-validation-observatory/bruno-exporter.mjs";
import { buildHar } from "../web/dynamic-validation-observatory/har-exporter.mjs";
import { normalizeBrowserExchangeV2 } from "../web/dynamic-validation-observatory/http-exchange.mjs";
import { acceptanceTemplate, sealPlatformAcceptance, validatePlatformAcceptance, verifyAcceptanceMatrix } from "../web/dynamic-validation-observatory/platform-acceptance.mjs";

const temp = await mkdtemp(join(tmpdir(), "dynamic-validation-core-"));
const execFileAsync = promisify(execFile);

function authorization(overrides = {}) {
  return {
    enabled: true,
    explicit_authorization: true,
    test_environment: true,
    target_base_url: "http://127.0.0.1:8080/app",
    ...overrides,
  };
}

function passingAcceptance(platformName) {
  const record = acceptanceTemplate(platformName, { now: new Date("2026-08-31T00:00:00.000Z"), nodeVersion: "22.0.0" });
  Object.assign(record.host, { os_version: `${platformName}-fixture`, chrome_version: "144.0.0.0", bruno_desktop_version: "4.0.0" });
  Object.assign(record.authorization, { explicit: true, loopback_only: true, target_origin: "http://127.0.0.1:8080" });
  Object.assign(record.p2_browser_ownership, {
    status: "PASS", chrome_144_or_newer: true, remote_debugging_confirmed: true, profile_visibility_warning_confirmed: true,
    task_page_created: true, task_page_closed: true, preexisting_pages_unchanged: true, risk_escalated_to_isolated_browser: true,
    isolated_browser_closed: true, shared_chrome_remained_running: true, headless_isolated_verified: platformName === "linux" ? true : null,
    proof_sha256: ["1".repeat(64)],
  });
  Object.assign(record.p4_bruno_desktop, {
    status: "PASS", archive_sha256: "2".repeat(64), opened_as_opencollection: true, request_semantics_preserved: true,
    repeated_query_parameters_preserved: true, environment_values_supplied_locally: true, secrets_absent_from_collection: true,
    requests_executed_against_loopback: true, expected_responses_observed: true, temporary_env_removed: true, proof_sha256: ["3".repeat(64)],
  });
  record.operator_confirmation = true;
  return record;
}

try {
  assert.equal(authorizeDynamicTask({}).status, "SKIPPED");
  assert.equal(authorizeDynamicTask(authorization()).status, "AUTHORIZED");
  assert.equal(authorizeDynamicTask(authorization({ target_base_url: "https://example.com" })).status, "SKIPPED");
  assert.equal(authorizeDynamicTask(authorization({ target_base_url: "http://user:pass@127.0.0.1:8080" })).status, "SKIPPED");
  assert.equal(authorizeDynamicTask({
    ...authorization(),
    accounts: { attacker: { username: "same", password: "a" }, victim: { username: "same", password: "b" } },
  }, { requireAccounts: true }).status, "SKIPPED");

  assert.equal(chooseBrowserMode({ requested: "auto", platform: "win32", desktopAvailable: true }).mode, "shared_tab");
  assert.equal(chooseBrowserMode({ requested: "shared_tab", riskSignals: ["stored_xss"] }).mode, "isolated_browser");
  assert.deepEqual(chooseBrowserMode({ requested: "auto", platform: "linux", desktopAvailable: false }), {
    mode: "isolated_browser", headless: true, escalated: true, reason: "headless-server",
  });
  const windowsMcp = chromeDevtoolsMcpDefinition({ mode: "shared_tab", headless: false }, { platform: "win32", packageSpec: "chrome-devtools-mcp@fixture" });
  assert.equal(windowsMcp.command[0], "npx.cmd");
  assert(windowsMcp.command.includes("--auto-connect"));
  assert(!windowsMcp.command.includes("--isolated=true"));
  assert.equal(sharedChromeReadiness({ chromeMajorVersion: 143, remoteDebuggingEnabled: true, profileConnectionConfirmed: true }).ready, false);
  assert.equal(sharedChromeReadiness({ chromeMajorVersion: 144, remoteDebuggingEnabled: true, profileConnectionConfirmed: true }).ready, true);
  const sharedBroker = new BrowserSessionBroker();
  assert.throws(() => sharedBroker.create({ requested: "shared_tab" }), error => error.code === "shared-chrome-not-ready");
  const sharedSession = sharedBroker.create({ requested: "shared_tab", chromeMajorVersion: 144, remoteDebuggingEnabled: true, profileConnectionConfirmed: true });
  assert.match(sharedSession.connection_warning, /其他页面/);

  const cleanup = [];
  const broker = new BrowserSessionBroker({
    controller: {
      closePage: async id => cleanup.push(`page:${id}`),
      closeContext: async id => cleanup.push(`context:${id}`),
      closeBrowser: async id => cleanup.push(`browser:${id}`),
    },
  });
  const session = broker.create({ requested: "isolated_context" });
  broker.registerPage(session.id, 12);
  await broker.close(session.id);
  assert.deepEqual(cleanup, ["page:12", `context:${session.context_name}`]);

  const bestEffortCleanup = [];
  const failingBroker = new BrowserSessionBroker({ controller: {
    closePage: async id => { bestEffortCleanup.push(`page:${id}`); throw new Error("page stuck"); },
    closeBrowser: async id => bestEffortCleanup.push(`browser:${id}`),
  } });
  const failingSession = failingBroker.create({ requested: "isolated_browser" });
  failingBroker.registerPage(failingSession.id, 99);
  await assert.rejects(() => failingBroker.close(failingSession.id), error => error.code === "browser-session-cleanup-failed");
  assert.deepEqual(bestEffortCleanup, ["page:99", `browser:${failingSession.id}`]);
  assert.equal(failingBroker.get(failingSession.id).status, "cleanup_failed");

  const requestBody = JSON.stringify({ marker: "proof-001", password: "[REDACTED]" });
  const responseBody = JSON.stringify({ ok: true, password: "[REDACTED]" });
  const first = {
    schema_version: 2,
    artifact_type: "HTTP_EXCHANGE_V2",
    exchange_id: "http_fixture-first",
    parent_exchange_id: null,
    request_session_id: "browser-context",
    source: "chrome_devtools_mcp",
    started_at: "2026-08-31T00:00:00.000Z",
    duration_ms: 12,
    request: {
      method: "POST",
      url: "http://127.0.0.1:8080/api/profile?accessToken=%5BREDACTED%5D&tag=one&tag=two",
      headers: [{ name: "Content-Type", value: "application/json" }, { name: "Authorization", value: "[REDACTED]" }],
      body: { media_type: "application/json", text: requestBody, sha256: createHash("sha256").update(requestBody).digest("hex"), size: Buffer.byteLength(requestBody), truncated: false },
    },
    response: {
      status: 200,
      status_text: "OK",
      headers: [{ name: "Content-Type", value: "application/json" }, { name: "Set-Cookie", value: "[REDACTED]" }],
      body: { media_type: "application/json", text: responseBody, sha256: createHash("sha256").update(responseBody).digest("hex"), size: Buffer.byteLength(responseBody), truncated: false },
      error: null,
    },
    redirect_chain: [],
    evidence_binding: { artifact_id: "ev-http-001", sequence: 1, phase: "APP_INPUT_SUBMISSION", step_id: null, browser_context_id: "browser-context" },
    sanitized: true,
  };
  const history = new RequestHistoryStore({ stateRoot: temp });
  await history.append(first);
  assert.equal(first.schema_version, 2);
  assert.equal(first.request.headers[1].value, "[REDACTED]");
  assert.equal(first.request.body.sha256, createHash("sha256").update(first.request.body.text).digest("hex"));
  assert.equal(first.response.body.sha256, createHash("sha256").update(first.response.body.text).digest("hex"));
  assert.equal(new URL(first.request.url).searchParams.getAll("tag").length, 2);
  const historyText = await readFile(join(temp, "http-exchanges.jsonl"), "utf8");
  assert.equal((await history.list()).length, 1);
  assert.equal(historyText.includes("[REDACTED]"), true);

  const legacyExchange = structuredClone(first);
  legacyExchange.started_at = "2026-08-31T00:00:00.000Z";
  legacyExchange.request.url = "http://127.0.0.1:8080/api/profile?accessToken=legacy-query-secret&tag=one&tag=two";
  legacyExchange.request.headers[1].value = "Bearer legacy-header-secret";
  legacyExchange.request.body.text = JSON.stringify({ marker: "proof-001", clientSecret: "legacy-body-secret" });
  const archive = buildOpenCollectionArchive([legacyExchange], { generatedAt: new Date("2026-08-31T00:00:00.000Z") });
  assert.equal(archive.filename, "dynamic-validation-20260831T000000Z.zip");
  const archiveFiles = Object.fromEntries(Object.entries(unzipSync(archive.bytes)).map(([path, bytes]) => [path, strFromU8(bytes)]));
  const archiveText = Object.values(archiveFiles).join("\n");
  assert.equal(archiveText.includes("legacy-query-secret"), false);
  assert.equal(archiveText.includes("legacy-header-secret"), false);
  assert.equal(archiveText.includes("legacy-body-secret"), false);
  assert.match(archiveText, /process\.env\.DYNVAL_001_AUTHORIZATION/);
  assert.match(archiveText, /process\.env\.DYNVAL_001_ACCESSTOKEN/);
  const rootName = archive.collection_name;
  assert.equal(parse(archiveFiles[`${rootName}/opencollection.yml`]).opencollection, "1.0.0");
  assert.equal(parse(archiveFiles[`${rootName}/environments/local.yml`]).variables[0].value, "http://127.0.0.1:8080");
  const requestPath = Object.keys(archiveFiles).find(path => path.startsWith(`${rootName}/requests/`));
  const requestYaml = parse(archiveFiles[requestPath]);
  assert.equal(requestYaml.http.method, "POST");
  assert.match(requestYaml.http.url, /^\{\{baseUrl\}\}\/api\/profile/);
  assert.equal((requestYaml.http.url.match(/tag=/g) ?? []).length, 2);
  assert.equal(requestYaml.docs.content.includes("legacy-header-secret"), false);
  const secondOrigin = structuredClone(legacyExchange);
  secondOrigin.exchange_id = "http_demo-second";
  secondOrigin.started_at = "2026-08-31T00:00:01.000Z";
  secondOrigin.parent_exchange_id = legacyExchange.exchange_id;
  secondOrigin.request.url = "http://127.0.0.1:9090/other";
  secondOrigin.request.headers[1].value = "[REDACTED]";
  secondOrigin.request.body.text = JSON.stringify({ marker: "proof-002" });
  const batchArchive = buildOpenCollectionArchive([secondOrigin, legacyExchange], { generatedAt: new Date("2026-08-31T00:00:01.000Z") });
  const batchFiles = Object.fromEntries(Object.entries(unzipSync(batchArchive.bytes)).map(([path, bytes]) => [path, strFromU8(bytes)]));
  const batchEnvironment = parse(batchFiles[`${batchArchive.collection_name}/environments/local.yml`]);
  assert.deepEqual(batchEnvironment.variables, [
    { name: "baseUrl", value: "http://127.0.0.1:8080" },
    { name: "baseUrl2", value: "http://127.0.0.1:9090" },
  ]);
  assert.equal(Object.keys(batchFiles).filter(path => path.includes("/requests/")).length, 2);
  assert.throws(() => buildOpenCollectionArchive([]), error => error.code === "bruno-export-count-invalid");
  assert.throws(() => buildOpenCollectionArchive(Array.from({ length: 101 }, (_, index) => ({ ...legacyExchange, exchange_id: `http_many-${index}` }))), error => error.code === "bruno-export-count-invalid");

  const har = buildHar([legacyExchange], { generatedAt: new Date("2026-08-31T00:00:00.000Z") });
  assert.equal(har.filename, "dynamic-validation-20260831T000000Z.har");
  assert.equal(JSON.stringify(har.document).includes("legacy-header-secret"), false);
  assert.equal(JSON.stringify(har.document).includes("legacy-body-secret"), false);
  assert.equal(har.document.log.entries[0].request.cookies.length, 0);

  const normalizedBrowser = normalizeBrowserExchangeV2({
    schema_version: 1, artifact_type: "SANITIZED_HTTP_EXCHANGE", exchange_id: "http-001", sequence: 2, phase: "VICTIM_VIEW",
    browser_context_id: "victim-context", started_at: "2026-08-31T00:00:00.000Z", duration_ms: 4.6,
    request: { method: "GET", url: "http://127.0.0.1:8080/view", headers: [], body: null },
    response: { status: 200, status_text: "OK", headers: [], body: { media_type: "text/plain", text: "proof", truncated: false }, error: null },
  }, { artifact_id: "ev-http-001", sequence: 2, phase: "VICTIM_VIEW" });
  assert.equal(normalizedBrowser.artifact_type, "HTTP_EXCHANGE_V2");
  assert.equal(normalizedBrowser.source, "chrome_devtools_mcp");
  assert.equal(normalizedBrowser.evidence_binding.artifact_id, "ev-http-001");
  assert.equal(normalizedBrowser.response.body.size, 5);

  const cli = join(process.cwd(), "scripts", "dynamic-validation-cli.mjs");
  const cliHelp = (await execFileAsync(process.execPath, [cli, "help"], { encoding: "utf8" })).stdout;
  assert.match(cliHelp, /dynamic-validation-cli\.mjs list/);
  assert.doesNotMatch(cliHelp, /dynamic-validation-cli\.mjs send/);
  const doctor = JSON.parse((await execFileAsync(process.execPath, [cli, "doctor"], { encoding: "utf8" })).stdout);
  assert.equal(doctor.status, "READY");
  assert.deepEqual(doctor.deployment, { mode: "native_process", container_runtime: "DISABLED", supported_hosts: ["windows", "linux"] });
  const skippedSpec = join(temp, "skipped-spec.json");
  await writeFile(skippedSpec, JSON.stringify({ enabled: false, authorization: {} }), "utf8");
  const skippedRun = JSON.parse((await execFileAsync(process.execPath, [cli, "run", "--spec", skippedSpec], { encoding: "utf8" })).stdout);
  assert.equal(skippedRun.status, "SKIPPED");

  const windowsAcceptance = sealPlatformAcceptance(passingAcceptance("windows"), { currentRuntime: "win32", now: new Date("2026-08-31T01:00:00.000Z") });
  const linuxAcceptance = sealPlatformAcceptance(passingAcceptance("linux"), { currentRuntime: "linux", now: new Date("2026-08-31T01:00:00.000Z") });
  assert.equal(validatePlatformAcceptance(windowsAcceptance, { requirePass: true }).status, "PASS");
  assert.equal(verifyAcceptanceMatrix(windowsAcceptance, linuxAcceptance).status, "PASS");
  assert.throws(() => sealPlatformAcceptance(passingAcceptance("windows"), { currentRuntime: "darwin" }), error => error.code === "acceptance-evidence-invalid");
  const secretAcceptance = passingAcceptance("linux");
  secretAcceptance.password = "must-not-persist";
  assert.equal(validatePlatformAcceptance(secretAcceptance, { requirePass: true }).issues.some(item => item.code === "acceptance-sensitive-key-forbidden"), true);
  const containerAcceptance = passingAcceptance("linux");
  containerAcceptance.p2_browser_ownership.container_runtime_used = true;
  assert.equal(validatePlatformAcceptance(containerAcceptance, { requirePass: true }).issues.some(item => item.code === "acceptance-browser-cleanup-invalid"), true);
  const windowsEvidencePath = join(temp, "windows-acceptance.json");
  const linuxEvidencePath = join(temp, "linux-acceptance.json");
  const templatePath = join(temp, "acceptance-template.json");
  await execFileAsync(process.execPath, [cli, "acceptance", "template", "--platform", "linux", "--output", templatePath], { encoding: "utf8" });
  assert.equal(JSON.parse(await readFile(templatePath, "utf8")).p2_browser_ownership.status, "PENDING");
  await writeFile(windowsEvidencePath, JSON.stringify(windowsAcceptance), "utf8");
  await writeFile(linuxEvidencePath, JSON.stringify(linuxAcceptance), "utf8");
  const matrix = JSON.parse((await execFileAsync(process.execPath, [cli, "acceptance", "verify", "--windows", windowsEvidencePath, "--linux", linuxEvidencePath], { encoding: "utf8" })).stdout);
  assert.equal(matrix.status, "PASS");

  const acceptanceSchema = JSON.parse(await readFile(join(process.cwd(), "web", "dynamic-validation-observatory", "platform-acceptance.schema.json"), "utf8"));
  assert.equal(acceptanceSchema.properties.platform.enum.includes("windows"), true);

  process.stdout.write(`${JSON.stringify({ complete: true, component: "dynamic-validation-core", cases: 69 })}\n`);
} finally {
  await rm(temp, { recursive: true, force: true });
}
