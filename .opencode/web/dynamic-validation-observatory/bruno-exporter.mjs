import { zipSync, strToU8 } from "fflate";
import { stringify } from "yaml";

const MAX_EXCHANGES = 100;
const MAX_UNCOMPRESSED_BYTES = 32 * 1024 * 1024;
const SECRET_HEADERS = new Set(["authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token"]);
const REDACTED = "[REDACTED]";

function secretName(value) {
  const normalized = String(value ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
  return /(?:authorization|cookie|password|passwd|secret|token|apikey|accesstoken|refreshtoken|clientsecret|session|sessionid)$/.test(normalized);
}

function exportError(message, statusCode, code) {
  return Object.assign(new Error(message), { statusCode, code });
}

function safeSegment(value, fallback = "request") {
  const normalized = String(value ?? "")
    .normalize("NFKC")
    .replace(/[\\/:*?"<>|\u0000-\u001f]/g, "-")
    .replace(/\s+/g, "-")
    .replace(/[^\p{L}\p{N}._-]+/gu, "-")
    .replace(/-+/g, "-")
    .replace(/^[-._]+|[-._]+$/g, "")
    .slice(0, 72);
  return normalized || fallback;
}

function variableName(sequence, label, suffix = "") {
  const safe = String(label ?? "SECRET").toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "SECRET";
  return `DYNVAL_${String(sequence).padStart(3, "0")}_${safe}${suffix}`;
}

function placeholderFactory(sequence, environmentKeys) {
  const counts = new Map();
  return label => {
    const base = variableName(sequence, label);
    const count = (counts.get(base) ?? 0) + 1;
    counts.set(base, count);
    const key = count === 1 ? base : `${base}_${count}`;
    environmentKeys.add(key);
    return `{{process.env.${key}}}`;
  };
}

function replaceRedactedText(value, makePlaceholder, label) {
  let index = 0;
  return String(value ?? "").replaceAll(REDACTED, () => makePlaceholder(`${label}_${++index}`));
}

function requestUrl(value, baseVariable, makePlaceholder) {
  const url = new URL(value);
  const parameters = new URLSearchParams();
  for (const [name, item] of url.searchParams.entries()) parameters.append(name, secretName(name) || item.includes(REDACTED) ? makePlaceholder(name) : item);
  url.search = parameters.toString();
  const search = url.search.replaceAll("%7B", "{").replaceAll("%7D", "}");
  return `${baseVariable}${url.pathname}${search}${url.hash}`;
}

function requestHeaders(headers, makePlaceholder) {
  return (headers ?? []).map(header => {
    const name = String(header.name ?? "");
    const value = String(header.value ?? "");
    const secret = SECRET_HEADERS.has(name.toLowerCase()) || secretName(name);
    return { name, value: secret ? makePlaceholder(name) : replaceRedactedText(value, makePlaceholder, name || "HEADER") };
  });
}

function jsonBody(text, makePlaceholder) {
  const visit = (value, key = "BODY") => {
    if (secretName(key)) return makePlaceholder(key);
    if (Array.isArray(value)) return value.map(item => visit(item, key));
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [childKey, visit(childValue, childKey)]));
    if (typeof value === "string" && value.includes(REDACTED)) return replaceRedactedText(value, makePlaceholder, key);
    return value;
  };
  return JSON.stringify(visit(JSON.parse(text)), null, 2);
}

function formBody(text, makePlaceholder) {
  return [...new URLSearchParams(text).entries()].map(([name, value]) => ({
    name,
    value: secretName(name) ? makePlaceholder(name) : replaceRedactedText(value, makePlaceholder, name),
  }));
}

function requestBody(body, headers, makePlaceholder) {
  if (!body?.text) return undefined;
  const headerType = headers.find(header => header.name.toLowerCase() === "content-type")?.value;
  const mediaType = String(headerType ?? body.media_type ?? "text/plain").split(";", 1)[0].trim().toLowerCase();
  const text = String(body.text);
  if (mediaType.includes("json")) {
    try { return { type: "json", data: jsonBody(text, makePlaceholder) }; }
    catch { return { type: "text", data: replaceRedactedText(text, makePlaceholder, "BODY_SECRET") }; }
  }
  if (mediaType === "application/x-www-form-urlencoded") {
    return { type: "form-urlencoded", data: formBody(text, makePlaceholder) };
  }
  if (mediaType.includes("xml")) return { type: "xml", data: replaceRedactedText(text, makePlaceholder, "BODY_SECRET") };
  return { type: "text", data: replaceRedactedText(text, makePlaceholder, "BODY_SECRET") };
}

function requestDocs(exchange) {
  const response = exchange.response ?? {};
  const body = response.body;
  return [
    "由动态验证平台的只读发包记录导出。原始凭据未包含在此集合中。",
    "",
    `- exchange_id: ${exchange.exchange_id}`,
    `- parent_exchange_id: ${exchange.parent_exchange_id ?? "无"}`,
    `- source: ${exchange.source}`,
    `- recorded_at: ${exchange.started_at}`,
    `- response_status: ${response.status ?? "ERR"}`,
    `- duration_ms: ${exchange.duration_ms}`,
    `- response_body_sha256: ${body?.sha256 ?? "无"}`,
    `- response_body_size: ${body?.size ?? 0}`,
    `- redirect_count: ${(exchange.redirect_chain ?? []).length}`,
  ].join("\n");
}

function requestFile(exchange, sequence, baseVariable, environmentKeys) {
  const makePlaceholder = placeholderFactory(sequence, environmentKeys);
  const headers = requestHeaders(exchange.request.headers, makePlaceholder);
  const body = requestBody(exchange.request.body, headers, makePlaceholder);
  const url = new URL(exchange.request.url);
  const pathName = safeSegment(url.pathname.split("/").filter(Boolean).slice(-2).join("-") || "root");
  const shortId = safeSegment(exchange.exchange_id.replace(/^http_/, "").slice(0, 8), "exchange");
  const name = `${exchange.request.method} ${url.pathname}`.slice(0, 120);
  const document = {
    info: { name, type: "http", seq: sequence },
    http: {
      method: exchange.request.method,
      url: requestUrl(exchange.request.url, `{{${baseVariable}}}`, makePlaceholder),
      ...(headers.length ? { headers } : {}),
      ...(body ? { body } : {}),
      auth: "none",
    },
    settings: { encodeUrl: true, timeout: 15000, followRedirects: true, maxRedirects: 5 },
    docs: { content: requestDocs(exchange), type: "text/markdown" },
  };
  return {
    path: `requests/${String(sequence).padStart(3, "0")}-${safeSegment(exchange.request.method, "HTTP")}-${pathName}-${shortId}.yml`,
    content: stringify(document, { lineWidth: 0 }),
  };
}

function archiveName(date) {
  return `dynamic-validation-${date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z")}`;
}

export function buildOpenCollectionArchive(exchanges, { generatedAt = new Date() } = {}) {
  if (!Array.isArray(exchanges) || !exchanges.length || exchanges.length > MAX_EXCHANGES) {
    throw exportError(`Bruno 导出必须包含 1-${MAX_EXCHANGES} 条记录。`, 422, "bruno-export-count-invalid");
  }
  const unique = new Map();
  for (const exchange of exchanges) {
    if (!exchange?.exchange_id || !exchange?.request?.url || !exchange?.request?.method) throw exportError("HTTP exchange 结构无效。", 422, "bruno-export-exchange-invalid");
    unique.set(exchange.exchange_id, exchange);
  }
  const ordered = [...unique.values()].sort((left, right) => String(left.started_at).localeCompare(String(right.started_at)) || left.exchange_id.localeCompare(right.exchange_id));
  const name = archiveName(generatedAt);
  const origins = [...new Set(ordered.map(exchange => new URL(exchange.request.url).origin))];
  const baseVariables = new Map(origins.map((origin, index) => [origin, index === 0 ? "baseUrl" : `baseUrl${index + 1}`]));
  const environmentKeys = new Set();
  const files = new Map();
  files.set("opencollection.yml", stringify({
    opencollection: "1.0.0",
    info: { name: `Dynamic Validation Export ${generatedAt.toISOString()}` },
    bundled: false,
    extensions: { bruno: { ignore: [".env", ".env.example", "README.md"] } },
  }, { lineWidth: 0 }));
  files.set("environments/local.yml", stringify({
    name: "local",
    variables: origins.map(origin => ({ name: baseVariables.get(origin), value: origin })),
  }, { lineWidth: 0 }));
  ordered.forEach((exchange, index) => {
    const file = requestFile(exchange, index + 1, baseVariables.get(new URL(exchange.request.url).origin), environmentKeys);
    files.set(file.path, file.content);
  });
  files.set(".env.example", `${[...environmentKeys].sort().map(key => `${key}=`).join("\n")}${environmentKeys.size ? "\n" : ""}`);
  files.set("README.md", [
    "# 动态验证请求导出",
    "",
    "本目录是 OpenCollection 1.0.0 集合，需要 Bruno 3.0 或更高版本。",
    "",
    "1. 解压 ZIP，并在 Bruno 中打开解压后的集合目录。",
    "2. 选择 `local` 环境。",
    "3. 如 `.env.example` 包含变量，复制为 `.env` 并仅在本机填写凭据。",
    "4. 运行前确认目标仍是授权的 loopback 测试环境。",
    "",
    "导出文件不包含原始认证凭据、响应头或响应正文。Bruno 本身不会继承平台的 loopback 安全门禁。",
    "",
  ].join("\n"));
  let uncompressedBytes = 0;
  const archiveEntries = {};
  for (const [path, content] of files) {
    const bytes = strToU8(content);
    uncompressedBytes += bytes.length;
    if (uncompressedBytes > MAX_UNCOMPRESSED_BYTES) throw exportError("Bruno 导出内容超过 32 MiB。", 413, "bruno-export-too-large");
    archiveEntries[`${name}/${path}`] = [bytes, { level: 6 }];
  }
  return {
    bytes: Buffer.from(zipSync(archiveEntries, { level: 6 })),
    filename: `${name}.zip`,
    collection_name: name,
    exchange_count: ordered.length,
  };
}

export const BRUNO_EXPORT_LIMITS = Object.freeze({ max_exchanges: MAX_EXCHANGES, max_uncompressed_bytes: MAX_UNCOMPRESSED_BYTES });
