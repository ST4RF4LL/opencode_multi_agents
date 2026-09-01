const MAX_EXCHANGES = 100;
const SECRET_HEADERS = new Set(["authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key", "x-auth-token"]);
const REDACTED = "[REDACTED]";

function secretName(value) {
  return /(?:authorization|cookie|password|passwd|secret|token|apikey|accesstoken|refreshtoken|clientsecret|session|sessionid)$/i.test(String(value ?? "").replace(/[^a-z0-9]/gi, ""));
}
function redactText(value) {
  const text = String(value ?? "");
  try {
    const visit = (item, key = "") => {
      if (secretName(key)) return REDACTED;
      if (Array.isArray(item)) return item.map(child => visit(child));
      if (item && typeof item === "object") return Object.fromEntries(Object.entries(item).map(([childKey, child]) => [childKey, visit(child, childKey)]));
      return item;
    };
    return JSON.stringify(visit(JSON.parse(text)));
  } catch {
    return text.replace(/\bBearer\s+[^\s,"']+/gi, `Bearer ${REDACTED}`)
      .replace(/((?:password|passwd|secret|token|authorization|cookie|api[_-]?key)\s*[:=]\s*)[^\s,&"']+/gi, `$1${REDACTED}`);
  }
}

function safeHeaders(headers) {
  return (headers ?? []).map(header => ({
    name: String(header.name ?? ""),
    value: SECRET_HEADERS.has(String(header.name ?? "").toLowerCase()) ? REDACTED : redactText(header.value),
  }));
}

function safeUrl(value) {
  const url = new URL(value);
  const query = [];
  for (const [name, item] of url.searchParams) query.push({ name, value: secretName(name) ? REDACTED : redactText(item) });
  url.search = new URLSearchParams(query.map(item => [item.name, item.value])).toString();
  return { url: url.href, query };
}

function entry(exchange) {
  const requestUrl = safeUrl(exchange.request.url);
  const requestHeaders = safeHeaders(exchange.request.headers);
  const responseHeaders = safeHeaders(exchange.response?.headers);
  const requestBody = exchange.request.body;
  const responseBody = exchange.response?.body;
  const duration = Math.max(0, Number(exchange.duration_ms) || 0);
  return {
    startedDateTime: exchange.started_at,
    time: duration,
    request: {
      method: exchange.request.method,
      url: requestUrl.url,
      httpVersion: "HTTP/1.1",
      headers: requestHeaders,
      queryString: requestUrl.query,
      cookies: [],
      headersSize: -1,
      bodySize: requestBody?.size ?? (requestBody?.text ? Buffer.byteLength(requestBody.text) : 0),
      ...(requestBody ? { postData: { mimeType: requestBody.media_type, text: redactText(requestBody.text) } } : {}),
    },
    response: {
      status: exchange.response?.status ?? 0,
      statusText: exchange.response?.status_text ?? "",
      httpVersion: "HTTP/1.1",
      headers: responseHeaders,
      cookies: [],
      content: {
        size: responseBody?.size ?? (responseBody?.text ? Buffer.byteLength(responseBody.text) : 0),
        mimeType: responseBody?.media_type ?? "application/octet-stream",
        text: redactText(responseBody?.text ?? ""),
      },
      redirectURL: exchange.redirect_chain?.at(-1)?.to ?? "",
      headersSize: -1,
      bodySize: responseBody?.size ?? -1,
    },
    cache: {},
    timings: { send: 0, wait: duration, receive: 0 },
    comment: `dynamic-validation exchange_id=${exchange.exchange_id}; source=${exchange.source}; sanitized=true`,
    _dynval: { exchange_id: exchange.exchange_id, parent_exchange_id: exchange.parent_exchange_id ?? null, source: exchange.source, evidence_binding: exchange.evidence_binding ?? null },
  };
}

export function buildHar(exchanges, { generatedAt = new Date() } = {}) {
  if (!Array.isArray(exchanges) || exchanges.length < 1 || exchanges.length > MAX_EXCHANGES) {
    throw Object.assign(new Error(`HAR 导出必须包含 1-${MAX_EXCHANGES} 条记录。`), { statusCode: 422, code: "har-export-count-invalid" });
  }
  const unique = [...new Map(exchanges.map(exchange => [exchange?.exchange_id, exchange])).values()];
  if (unique.some(exchange => !exchange?.exchange_id || !exchange?.request?.url || !exchange?.request?.method)) {
    throw Object.assign(new Error("HTTP exchange 结构无效。"), { statusCode: 422, code: "har-export-exchange-invalid" });
  }
  const document = {
    log: {
      version: "1.2",
      creator: { name: "Dynamic Vulnerability Validator", version: "1" },
      comment: "仅包含脱敏后的授权测试请求与响应；不包含 Cookie 对象。",
      entries: unique.sort((a, b) => String(a.started_at).localeCompare(String(b.started_at))).map(entry),
    },
  };
  const stamp = generatedAt.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  return { bytes: Buffer.from(`${JSON.stringify(document, null, 2)}\n`), filename: `dynamic-validation-${stamp}.har`, document };
}
