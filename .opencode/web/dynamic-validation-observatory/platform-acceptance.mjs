import { createHash } from "node:crypto";
import { platform as runtimePlatform, arch } from "node:os";

const ACCEPTANCE_PLATFORMS = new Set(["windows", "linux"]);
const PLATFORM_RUNTIME = Object.freeze({ windows: "win32", linux: "linux" });
const DIGEST = /^[a-f0-9]{64}$/;
const SECRET_KEYS = new Set(["password", "passwd", "secret", "token", "cookie", "credentialvalue", "apikey", "sessionvalue", "authorizationvalue"]);
const SECRET_VALUE = /\bBearer\s+[A-Za-z0-9._~+\/-]+|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/i;

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
}

function digestWithoutSeal(value) {
  const copy = structuredClone(value);
  delete copy.evidence_digest;
  return createHash("sha256").update(JSON.stringify(canonical(copy))).digest("hex");
}

function issue(code, path, message) {
  return { code, path, message };
}

function major(value) {
  const match = String(value ?? "").match(/(\d+)(?:\.\d+){1,3}/);
  return match ? Number(match[1]) : null;
}

function loopbackOrigin(value) {
  try {
    const url = new URL(value);
    return ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
      && ["http:", "https:"].includes(url.protocol)
      && !url.username && !url.password && url.href === `${url.origin}/`;
  } catch {
    return false;
  }
}

function scanSensitive(value, path = "") {
  if (Array.isArray(value)) return value.flatMap((item, index) => scanSensitive(item, `${path}/${index}`));
  if (!value || typeof value !== "object") return typeof value === "string" && SECRET_VALUE.test(value)
    ? [issue("acceptance-sensitive-value-forbidden", path || "/", "验收证据疑似包含认证值。")] : [];
  return Object.entries(value).flatMap(([key, child]) => [
    ...(SECRET_KEYS.has(key.toLowerCase().replace(/[^a-z0-9]/g, "")) ? [issue("acceptance-sensitive-key-forbidden", `${path}/${key}`, "验收证据禁止包含凭据形态字段。")] : []),
    ...scanSensitive(child, `${path}/${key}`),
  ]);
}

function proofDigests(value, path, issues) {
  if (!Array.isArray(value) || value.length < 1 || value.some(item => !DIGEST.test(item))) {
    issues.push(issue("acceptance-proof-digests-invalid", path, "必须至少提供一个脱敏证据文件的 SHA-256。"));
  }
}

export function acceptanceTemplate(platform, { now = new Date(), nodeVersion = process.versions.node } = {}) {
  if (!ACCEPTANCE_PLATFORMS.has(platform)) throw Object.assign(new Error("验收平台必须是 windows 或 linux。"), { code: "acceptance-platform-invalid" });
  return {
    schema_version: 1,
    artifact_type: "DYNAMIC_VALIDATION_PLATFORM_ACCEPTANCE",
    acceptance_id: `dynval-${platform}-${now.toISOString().slice(0, 10)}`,
    platform,
    recorded_at: null,
    host: {
      os_version: "",
      architecture: arch(),
      node_version: nodeVersion,
      chrome_version: "",
      chrome_devtools_mcp_version: "1.8.0",
      bruno_desktop_version: "",
    },
    authorization: { explicit: false, loopback_only: false, target_origin: "" },
    p2_browser_ownership: {
      status: "PENDING",
      chrome_144_or_newer: false,
      remote_debugging_confirmed: false,
      profile_visibility_warning_confirmed: false,
      task_page_created: false,
      task_page_closed: false,
      preexisting_pages_unchanged: false,
      risk_escalated_to_isolated_browser: false,
      isolated_browser_closed: false,
      shared_chrome_remained_running: false,
      headless_isolated_verified: platform === "windows" ? null : false,
      global_chrome_termination_used: false,
      container_runtime_used: false,
      cleanup_failures: [],
      proof_sha256: [],
    },
    p4_bruno_desktop: {
      status: "PENDING",
      archive_sha256: "",
      opened_as_opencollection: false,
      request_semantics_preserved: false,
      repeated_query_parameters_preserved: false,
      environment_values_supplied_locally: false,
      secrets_absent_from_collection: false,
      requests_executed_against_loopback: false,
      expected_responses_observed: false,
      temporary_env_removed: false,
      proof_sha256: [],
    },
    operator_confirmation: false,
    evidence_digest: null,
  };
}

export function validatePlatformAcceptance(value, { requirePass = false, expectedRuntime = null } = {}) {
  const issues = scanSensitive(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) return { valid: false, status: "INVALID", issues: [issue("acceptance-not-object", "/", "验收证据必须是 JSON 对象。")] };
  if (value.schema_version !== 1 || value.artifact_type !== "DYNAMIC_VALIDATION_PLATFORM_ACCEPTANCE") issues.push(issue("acceptance-identity-invalid", "/", "验收证据类型或版本无效。"));
  if (!/^dynval-(?:windows|linux)-\d{4}-\d{2}-\d{2}$/.test(value.acceptance_id ?? "")) issues.push(issue("acceptance-id-invalid", "/acceptance_id", "验收 ID 格式无效。"));
  if ((value.recorded_at !== null && Number.isNaN(Date.parse(value.recorded_at))) || (requirePass && typeof value.recorded_at !== "string")) issues.push(issue("acceptance-recorded-at-invalid", "/recorded_at", "封存时间无效。"));
  if (!ACCEPTANCE_PLATFORMS.has(value.platform)) issues.push(issue("acceptance-platform-invalid", "/platform", "平台必须是 windows 或 linux。"));
  if (requirePass && (!String(value.host?.os_version ?? "").trim() || !String(value.host?.architecture ?? "").trim())) issues.push(issue("acceptance-host-identity-missing", "/host", "必须记录目标操作系统版本和 CPU 架构。"));
  if (expectedRuntime && PLATFORM_RUNTIME[value.platform] !== expectedRuntime) issues.push(issue("acceptance-runtime-platform-mismatch", "/platform", "只能在对应目标操作系统封存验收证据。"));
  if (!Number.isInteger(major(value.host?.node_version)) || major(value.host?.node_version) < 20) issues.push(issue("acceptance-node-version-invalid", "/host/node_version", "Node.js 必须为 20 或更高版本。"));
  if (!Number.isInteger(major(value.host?.chrome_version)) || major(value.host?.chrome_version) < 144) issues.push(issue("acceptance-chrome-version-invalid", "/host/chrome_version", "Chrome 必须为 144 或更高版本。"));
  if (String(value.host?.chrome_devtools_mcp_version) !== "1.8.0") issues.push(issue("acceptance-mcp-version-invalid", "/host/chrome_devtools_mcp_version", "Chrome DevTools MCP 必须为固定版本 1.8.0。"));
  if (!Number.isInteger(major(value.host?.bruno_desktop_version)) || major(value.host?.bruno_desktop_version) < 4) issues.push(issue("acceptance-bruno-version-invalid", "/host/bruno_desktop_version", "Bruno Desktop 必须为 4.x 或更高版本。"));
  if (value.authorization?.explicit !== true || value.authorization?.loopback_only !== true || !loopbackOrigin(value.authorization?.target_origin)) issues.push(issue("acceptance-authorization-invalid", "/authorization", "必须记录用户显式授权的 loopback origin。"));
  const p2 = value.p2_browser_ownership ?? {};
  const requiredP2 = ["chrome_144_or_newer", "remote_debugging_confirmed", "profile_visibility_warning_confirmed", "task_page_created", "task_page_closed", "preexisting_pages_unchanged", "risk_escalated_to_isolated_browser", "isolated_browser_closed", "shared_chrome_remained_running"];
  if (p2.global_chrome_termination_used !== false || p2.container_runtime_used !== false || !Array.isArray(p2.cleanup_failures) || p2.cleanup_failures.length) issues.push(issue("acceptance-browser-cleanup-invalid", "/p2_browser_ownership", "不得使用全局 Chrome 终止或容器运行时，且受管资源清理失败列表必须为空。"));
  if (requirePass && (p2.status !== "PASS" || requiredP2.some(key => p2[key] !== true) || (value.platform === "linux" && p2.headless_isolated_verified !== true))) issues.push(issue("acceptance-p2-not-passed", "/p2_browser_ownership", "P2 浏览器归属与清理验收未全部通过。"));
  proofDigests(p2.proof_sha256, "/p2_browser_ownership/proof_sha256", issues);
  const p4 = value.p4_bruno_desktop ?? {};
  const requiredP4 = ["opened_as_opencollection", "request_semantics_preserved", "repeated_query_parameters_preserved", "environment_values_supplied_locally", "secrets_absent_from_collection", "requests_executed_against_loopback", "expected_responses_observed", "temporary_env_removed"];
  if (!DIGEST.test(p4.archive_sha256 ?? "")) issues.push(issue("acceptance-archive-digest-invalid", "/p4_bruno_desktop/archive_sha256", "OpenCollection ZIP 必须记录 SHA-256。"));
  if (requirePass && (p4.status !== "PASS" || requiredP4.some(key => p4[key] !== true))) issues.push(issue("acceptance-p4-not-passed", "/p4_bruno_desktop", "P4 Bruno Desktop 验收未全部通过。"));
  proofDigests(p4.proof_sha256, "/p4_bruno_desktop/proof_sha256", issues);
  if (requirePass && value.operator_confirmation !== true) issues.push(issue("acceptance-operator-confirmation-missing", "/operator_confirmation", "操作员必须确认验收记录准确且已脱敏。"));
  if (value.evidence_digest !== null && (!DIGEST.test(value.evidence_digest) || value.evidence_digest !== digestWithoutSeal(value))) issues.push(issue("acceptance-evidence-digest-invalid", "/evidence_digest", "验收证据摘要无效。"));
  return { valid: issues.length === 0, status: issues.length ? "INVALID" : requirePass ? "PASS" : "VALID", issues };
}

export function sealPlatformAcceptance(value, { currentRuntime = runtimePlatform(), now = new Date() } = {}) {
  const sealed = structuredClone(value);
  sealed.recorded_at = now.toISOString();
  sealed.evidence_digest = null;
  const result = validatePlatformAcceptance(sealed, { requirePass: true, expectedRuntime: currentRuntime });
  if (!result.valid) throw Object.assign(new Error(result.issues.map(item => item.message).join("；")), { code: "acceptance-evidence-invalid", issues: result.issues });
  sealed.evidence_digest = digestWithoutSeal(sealed);
  return sealed;
}

export function verifyAcceptanceMatrix(windows, linux) {
  const records = { windows, linux };
  const issues = [];
  for (const platform of ACCEPTANCE_PLATFORMS) {
    const value = records[platform];
    if (value?.platform !== platform) issues.push(issue("acceptance-matrix-platform-mismatch", `/${platform}`, `缺少 ${platform} 平台验收证据。`));
    const result = validatePlatformAcceptance(value, { requirePass: true });
    issues.push(...result.issues.map(item => ({ ...item, path: `/${platform}${item.path}` })));
    if (!DIGEST.test(value?.evidence_digest ?? "")) issues.push(issue("acceptance-matrix-unsealed", `/${platform}/evidence_digest`, "平台验收证据尚未封存。"));
  }
  return { schema_version: 1, status: issues.length ? "BLOCKED" : "PASS", platforms: ["windows", "linux"], issues };
}
