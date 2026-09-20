import { createHash } from "node:crypto";

export const PROTOCOL = "runtime-testing.v1";
export const PHASES = ["CONTACT", "EXPLORE", "CONFIRM", "CLEANUP"];
export const MODES = ["CONTACT_ONLY", "INTEGRATED_TESTING", "TARGETED_CONFIRMATION"];
export const ACTIONS = ["navigate", "normal_interaction", "test_input", "test_mutation"];
export const TERMINAL = new Set(["COMPLETED", "SKIPPED", "BLOCKED", "TIMED_OUT", "CANCELLED", "FAILED"]);
export const OUTCOMES = new Set(["SUPPORTED", "COUNTEREVIDENCE", "NOT_OBSERVED", "INCONCLUSIVE"]);
export const CLEANUP = new Set(["NOT_REQUIRED", "SUCCEEDED", "FAILED", "UNKNOWN"]);
export const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
export const SHA = /^[a-f0-9]{64}$/;
export function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  return value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
}
export function digest(value) {
  const copy = structuredClone(value); delete copy.artifact_digest;
  return createHash("sha256").update(JSON.stringify(canonical(copy))).digest("hex");
}
export function seal(value) { return { ...value, artifact_digest: digest(value) }; }
export function fail(code, message = code) { return Object.assign(new Error(message), { code, statusCode: 422 }); }
export function check(value, code, message) { if (!value) throw fail(code, message); }
export function text(value) { return typeof value === "string" && value.trim().length > 0; }
export function httpUrl(value) {
  try {
    if (typeof value !== "string" || !/^https?:\/\//i.test(value.trim()) || /[\s\\]/u.test(value.trim())) return null;
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol) || !url.hostname || url.username || url.password) return null;
    return url;
  } catch { return null; }
}

// Only environment input accepts a missing scheme; browser requests remain absolute.
function environmentUrl(value) {
  if (typeof value !== "string") return null;
  const input = value.trim();
  const shorthand = /^(?:\[[0-9a-f:.]+\]|[a-z0-9][a-z0-9.-]*)(?::\d+)?(?:[/?#]|$)/i.test(input);
  return httpUrl(shorthand ? `http://${input}` : input);
}

function parseEnvironment(context) {
  try { return { environment: JSON.parse(context) }; } catch {
    const input = context.trim();
    // Broken structured input must not fall back to a partial URL/account match.
    if (input.startsWith("{") || input.startsWith("[") && !/^\[[0-9a-f:.]+\](?::|\/|$)/i.test(input)) return { reason: "ENVIRONMENT_FORMAT_INVALID" };
    const field = labels => context.match(new RegExp(`^[\\t ]*(?:[-*][\\t ]+)?(?:\\*\\*)?(?:${labels})(?:\\*\\*)?[\\t ]*[:：][\\t ]*([^\\r\\n]*)$`, "mi"))?.[1]?.trim();
    const primary = field("url|target_base_url|base_url|地址|环境地址|测试地址|测试环境地址|目标地址|应用地址|入口地址");
    const clean = value => value.replace(/^[<\("'`]+|[>\)"'`，；。]+$/g, "");
    let targets;
    if (primary != null) targets = [environmentUrl(clean(primary.split(/[\s,，;；。]/u)[0]))];
    else {
      const candidates = [...context.matchAll(/(?:[a-z][a-z0-9+.-]*:\/\/[^\s<>"'`,，;；。)]+|(?<![\w.@:/-])(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:.]+\]|[a-z0-9-]+(?:\.[a-z0-9-]+)+):\d+(?:[/?#][^\s<>"'`,，;；。)]*)?)/gi)].map(match => match[0]);
      if (!candidates.length) {
        const direct = environmentUrl(clean(input));
        if (!direct) return { reason: "ENVIRONMENT_URL_MISSING" };
        targets = [direct];
      } else targets = candidates.map(value => environmentUrl(clean(value)));
    }
    if (targets.some(target => !target)) return { reason: "ENVIRONMENT_URL_INVALID" };
    if (new Set(targets.map(target => target.origin)).size > 1) return { reason: "ENVIRONMENT_URL_AMBIGUOUS" };
    const username = field("username|用户名|用户|测试账号|账号");
    return { environment: { url: targets[0].href,
      accounts: username ? [{ id: "shared", username, password: field("password|测试密码|密码") }] : [],
      instructions: context, test_data_scope: field("test_data_scope|测试数据范围"), cleanup_instructions: field("cleanup_instructions|清理说明") } };
  }
}

// A protocol must be selected explicitly; old quick opt-ins never grant new capabilities.
export function selection(input = {}) {
  const value = input.runtime_testing;
  if (value == null) return null;
  check(value.protocol === PROTOCOL && MODES.includes(value.mode), "runtime-selection-invalid", "动态参与范围无效。");
  const minutes = value.budget_minutes ?? 60;
  check(Number.isInteger(minutes) && minutes >= 10 && minutes <= 240, "runtime-budget-invalid", "动态总预算必须为 10–240 分钟。");
  const actions = value.allowed_actions ?? ["navigate"];
  check(Array.isArray(actions) && actions.includes("navigate") && new Set(actions).size === actions.length && actions.every(action => ACTIONS.includes(action)), "runtime-actions-invalid");
  check(["anonymous", "shared", "distinct"].includes(value.identity_mode ?? "anonymous"), "runtime-identity-mode-invalid");
  return { protocol: PROTOCOL, mode: value.mode, budget_minutes: minutes, allowed_actions: actions,
    identity_mode: value.identity_mode ?? "anonymous", explicit_authorization: value.explicit_authorization === true };
}

export function authorize({ auditId, selected, enabled, context = "", sourceBinding = null, scopeDigest = null }) {
  const base = { protocol: PROTOCOL, audit_id: auditId, source_binding: sourceBinding, scope_digest: scopeDigest,
    mode: selected?.mode ?? "CONTACT_ONLY", budget_ms: (selected?.budget_minutes ?? 60) * 60_000,
    cleanup_reserve_ms: Math.min(600_000, Math.floor((selected?.budget_minutes ?? 60) * 60_000 / 6)),
    allowed_actions: selected?.allowed_actions ?? [], identities: [], origins: [], environment_revision: null };
  const skipped = reason => ({ public: seal({ ...base, status: "SKIPPED", reason }), private: null });
  if (typeof context !== "string" || !context.trim()) return skipped("ENVIRONMENT_NOT_PROVIDED");
  if (selected?.protocol !== PROTOCOL || enabled !== true || selected.explicit_authorization !== true) return skipped("DYNAMIC_NOT_AUTHORIZED");
  const { environment, reason } = parseEnvironment(context);
  if (reason) return skipped(reason);
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) return skipped("ENVIRONMENT_FORMAT_INVALID");
  const targetValue = environment.url ?? environment.target_base_url;
  if (!text(targetValue)) return skipped("ENVIRONMENT_URL_MISSING");
  const target = environmentUrl(targetValue);
  if (!target) return skipped("ENVIRONMENT_URL_INVALID");
  const origins = environment.origins ?? [target.origin];
  if (!Array.isArray(origins) || origins.length < 1 || origins.length > 8 || origins.some(origin => httpUrl(origin)?.origin !== origin) || !origins.includes(target.origin)) return skipped("ENVIRONMENT_ORIGINS_INVALID");
  const accounts = environment.accounts ?? [];
  const identityMode = selected.identity_mode ?? "anonymous";
  if (environment.requires_login === true && identityMode === "anonymous") return skipped("REQUIRED_IDENTITIES_MISSING");
  if (identityMode !== "anonymous" && (!Array.isArray(accounts) || accounts.length < (identityMode === "distinct" ? 2 : 1)
    || accounts.some(account => !ID.test(account?.id ?? "") || !text(account?.username) || !text(account?.password))
    || new Set(accounts.map(account => account.id)).size !== accounts.length
    || (identityMode === "distinct" && new Set(accounts.map(account => account.username)).size < 2))) return skipped("REQUIRED_IDENTITIES_MISSING");
  if (!Array.isArray(accounts) || identityMode === "anonymous" && accounts.length) return skipped("IDENTITY_SCOPE_MISMATCH");
  if (selected.allowed_actions.includes("test_mutation") && (!text(environment.test_data_scope) || !text(environment.cleanup_instructions))) return skipped("REQUIRED_MUTATION_SCOPE_MISSING");
  const identities = identityMode === "anonymous" ? [{ id: "anonymous", role: "anonymous", tenant: null }]
    : accounts.map(account => ({ id: account.id, role: String(account.role ?? "test-user").slice(0, 120), tenant: account.tenant == null ? null : String(account.tenant).slice(0, 120) }));
  const revision = String(environment.revision ?? "operator-unspecified").slice(0, 200);
  const value = seal({ ...base, status: "AUTHORIZED", reason: null, origins: [...new Set(origins)].sort(), identities,
    context_digest: createHash("sha256").update(context).digest("hex"),
    test_data_scope: selected.allowed_actions.includes("test_mutation") ? environment.test_data_scope : null,
    environment_revision: revision, deployment_binding: environment.source_revision === sourceBinding && sourceBinding != null ? "OPERATOR_ASSERTED" : "UNKNOWN" });
  return { public: value, private: { url: target.href, accounts: identityMode === "anonymous" ? [] : accounts,
    instructions: String(environment.instructions ?? environment.login_instructions ?? ""),
    cleanup_instructions: String(environment.cleanup_instructions ?? "") } };
}

export function validatePacket(packet, authorization) {
  check(packet?.protocol === PROTOCOL && ID.test(packet.id ?? "") && packet.id.length <= 96 && PHASES.includes(packet.phase), "packet-invalid");
  check(packet.authorization_digest === authorization.artifact_digest && packet.environment_revision === authorization.environment_revision, "packet-authorization-binding-invalid");
  check(packet.audit_id === authorization.audit_id, "packet-audit-mismatch");
  check(Array.isArray(packet.identity_ids) && packet.identity_ids.length > 0 && new Set(packet.identity_ids).size === packet.identity_ids.length
    && packet.identity_ids.every(id => authorization.identities.some(identity => identity.id === id)), "packet-identities-invalid");
  check(Number.isInteger(packet.budget_seconds) && packet.budget_seconds >= 10 && packet.budget_seconds <= 1800, "packet-budget-invalid");
  check(Array.isArray(packet.actions) && packet.actions.every(action => authorization.allowed_actions.includes(action)), "packet-actions-not-authorized");
  if (packet.phase === "CONTACT") check(packet.actions.every(action => ["navigate", "normal_interaction"].includes(action)), "contact-cannot-explore");
  if (authorization.mode === "CONTACT_ONLY") check(["CONTACT", "CLEANUP"].includes(packet.phase), "phase-not-authorized");
  if (authorization.mode === "TARGETED_CONFIRMATION") check(packet.phase !== "EXPLORE", "phase-not-authorized");
  check(text(packet.question) && text(packet.expected_behavior) && Array.isArray(packet.steps) && packet.steps.length > 0 && packet.steps.every(text), "packet-test-plan-required");
  check(Array.isArray(packet.counterchecks) && packet.counterchecks.every(text), "packet-counterchecks-invalid");
  if (["EXPLORE", "CONFIRM"].includes(packet.phase)) {
    check(ID.test(packet.hypothesis_id ?? "") && text(packet.focus_area_id) && SHA.test(packet.scope_digest ?? ""), "packet-focus-binding-required");
    check(packet.scope_digest === authorization.scope_digest, "packet-frozen-scope-mismatch");
    check(packet.counterchecks.length > 0, "packet-countercheck-required");
  }
  if (packet.phase === "CONFIRM") check(text(packet.finding_id) && SHA.test(packet.finding_object_digest ?? "") && text(packet.vulnerability_type_id), "confirmation-finding-required");
  if (packet.actions.includes("test_mutation")) check(text(packet.cleanup_plan) && text(packet.test_data_scope) && packet.test_data_scope === authorization.test_data_scope, "mutation-cleanup-required");
  return packet;
}

export function validateSubmission(value, packet, actionIds) {
  check(value && Object.keys(value).every(key => ["execution_status", "outcome", "cleanup_status", "summary", "evidence_ids", "observations", "gaps", "changes", "proof"].includes(key)), "submission-fields-invalid");
  check(value && ["COMPLETED", "SKIPPED", "BLOCKED"].includes(value.execution_status) && OUTCOMES.has(value.outcome) && CLEANUP.has(value.cleanup_status), "submission-status-invalid");
  check(text(value.summary) && /\p{Script=Han}/u.test(value.summary), "submission-chinese-summary-required");
  check(Array.isArray(value.evidence_ids) && new Set(value.evidence_ids).size === value.evidence_ids.length && value.evidence_ids.every(id => actionIds.has(id)), "submission-evidence-invalid");
  if (value.execution_status === "COMPLETED" && packet.phase === "CONTACT") check(value.evidence_ids.length > 0, "contact-evidence-required");
  check(Array.isArray(value.observations) && value.observations.every(text) && Array.isArray(value.gaps) && value.gaps.every(text), "submission-observations-invalid");
  check(Array.isArray(value.changes) && value.changes.every(change => text(change.marker) && text(change.resource) && ["SUCCEEDED", "FAILED", "UNKNOWN"].includes(change.cleanup_status)), "submission-change-ledger-required");
  if (value.outcome === "SUPPORTED") {
    check(value.execution_status === "COMPLETED" && value.evidence_ids.length > 0 && value.observations.length > 0, "supported-evidence-required");
    if (packet.phase === "CONFIRM") {
      const proof = value.proof;
      check(proof && ["application_input", "reachability", "attacker_influence", "boundary_failure", "impact", "countercheck"].every(key => text(proof[key])), "confirmation-proof-required");
    }
    if (packet.vulnerability_type_id === "JW-INJECT-06") check(value.proof && ["persisted_or_revisited", "victim_execution"].every(key => text(value.proof[key]))
      && packet.identity_ids.length >= 2 && value.proof.method === "REAL_APPLICATION_INPUT", "xss-application-proof-required");
  }
  if (value.changes.length) check(value.cleanup_status !== "NOT_REQUIRED", "cleanup-summary-mismatch");
  if (value.changes.some(change => ["FAILED", "UNKNOWN"].includes(change.cleanup_status))) check(["FAILED", "UNKNOWN"].includes(value.cleanup_status), "cleanup-summary-mismatch");
  if (packet.actions.includes("test_mutation") && value.execution_status === "COMPLETED") check(value.cleanup_status !== "NOT_REQUIRED", "mutation-cleanup-missing");
  return value;
}

export function redact(value, privateContext = {}) {
  let result = typeof value === "string" ? value : JSON.stringify(value);
  const secrets = (privateContext.accounts ?? []).flatMap(account => [account.username, account.password]).filter(text).sort((a, b) => b.length - a.length);
  for (const secret of secrets) result = result.replaceAll(secret, "[REDACTED]");
  return result.replace(/(authorization|cookie|set-cookie|password|passwd|token|secret|api[_-]?key)(\s*["']?\s*[:=]\s*)[^\n\r,}]+/gi, "$1$2[REDACTED]")
    .replace(/\bBearer\s+[\w.\-+/=]+/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/g, "[JWT_REDACTED]");
}
