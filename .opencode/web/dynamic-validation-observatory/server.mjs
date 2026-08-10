#!/usr/bin/env node

import { createServer as createHttpServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getValidationRun, listValidationRuns } from "./model.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(HERE, "../../..");
const PUBLIC_ROOT = join(HERE, "public");
const DEFAULT_RUNTIME_ROOT = join(PROJECT_ROOT, "reports", "validation-handoff", "runtime");
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const STATIC_FILES = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/index.html", ["index.html", "text/html; charset=utf-8"]],
  ["/app.js", ["app.js", "text/javascript; charset=utf-8"]],
  ["/styles.css", ["styles.css", "text/css; charset=utf-8"]],
]);

function json(response, status, value) {
  const body = `${JSON.stringify(value)}\n`;
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
  });
  response.end(body);
}

function securityHeaders(response) {
  response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
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

export function createValidationObservatoryServer({ runtimeRoot = DEFAULT_RUNTIME_ROOT } = {}) {
  const resolvedRuntimeRoot = resolve(runtimeRoot);
  return createHttpServer(async (request, response) => {
    securityHeaders(response);
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (request.method !== "GET") {
        json(response, 405, { error: "method-not-allowed" });
        return;
      }
      if (url.pathname === "/api/health") {
        json(response, 200, { ok: true, service: "dynamic-validation-observatory" });
        return;
      }
      if (url.pathname === "/api/runs") {
        const runs = await listValidationRuns(resolvedRuntimeRoot);
        json(response, 200, { runs, count: runs.length });
        return;
      }
      if (url.pathname.startsWith("/api/runs/")) {
        const id = decodeURIComponent(url.pathname.slice("/api/runs/".length));
        const run = await getValidationRun(resolvedRuntimeRoot, id);
        if (!run) {
          json(response, 404, { error: "run-not-found" });
          return;
        }
        json(response, 200, { run });
        return;
      }
      if (await staticResponse(response, url.pathname)) return;
      json(response, 404, { error: "not-found" });
    } catch (error) {
      json(response, 500, { error: "internal-error", message: error.message });
    }
  });
}

function parseArgs(argv) {
  const options = {
    host: process.env.DYNAMIC_VALIDATION_WEB_HOST ?? "127.0.0.1",
    port: Number(process.env.DYNAMIC_VALIDATION_WEB_PORT ?? 4173),
    runtimeRoot: process.env.DYNAMIC_VALIDATION_RUNTIME_ROOT ?? DEFAULT_RUNTIME_ROOT,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === "--host") options.host = argv[++index];
    else if (option === "--port") options.port = Number(argv[++index]);
    else if (option === "--runtime-root") options.runtimeRoot = argv[++index];
    else throw new Error(`Unknown argument: ${option}`);
  }
  if (!LOOPBACK_HOSTS.has(options.host)) throw new Error("The observatory may listen on loopback hosts only");
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65535) throw new Error("Invalid port");
  return options;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArgs(process.argv.slice(2));
    const server = createValidationObservatoryServer({ runtimeRoot: options.runtimeRoot });
    server.listen(options.port, options.host, () => {
      const address = server.address();
      const host = options.host === "::1" || options.host === "[::1]" ? `[${options.host.replaceAll("[", "").replaceAll("]", "")}]` : options.host;
      process.stdout.write(`动态验证观测台已启动：http://${host}:${address.port}\n`);
    });
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
