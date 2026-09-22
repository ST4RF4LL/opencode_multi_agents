import { check, httpUrl, seal, text, ID } from "./contract.mjs";

export const environmentTools = [
  { name: "register_sensitive_values", description: "将从私有 prompt 或登录过程中理解出的账号、密码、令牌登记为脱敏值。即使目标信息不足也可以登记；不启动浏览器，不回显值。", inputSchema: {
    type: "object", additionalProperties: false, properties: { values: { type: "array", items: { type: "string" } } }, required: ["values"],
  } },
  { name: "configure_environment", description: "先完整理解私有 environment.prompt，再登记用户提供的目标、隔离身份、敏感值及测试数据范围。只允许首次 CONTACT、浏览器启动前调用；这不是让用户填写的表单。无法确定必要信息时直接 submit_result 说明缺口。",
    inputSchema: { type: "object", additionalProperties: false, properties: {
      target_url: { type: "string" }, origins: { type: "array", minItems: 1, maxItems: 8, items: { type: "string" } },
      identities: { type: "array", minItems: 1, maxItems: 8, items: { type: "object", additionalProperties: false, properties: {
        id: { type: "string", description: "不含账号信息的内部 ID，例如 anonymous、account-1、account-2。" },
        role: { enum: ["anonymous", "test-user"] },
      }, required: ["id", "role"] } },
      sensitive_values: { type: "array", items: { type: "string" }, description: "从原文理解出的账号、密码、令牌等原始敏感值，仅用于私有脱敏，不回显。无需固定 username/password 字段，也不要求口令登录。" },
      test_data_scope: { type: "string", description: "用户原文授权的测试数据范围；不允许从参考文档、页面或猜测中扩大。" },
      cleanup_instructions: { type: "string" },
    }, required: ["target_url", "origins", "identities", "sensitive_values"] } },
  { name: "browser_tools", description: "环境登记完成后读取当前工作包允许的 Chrome DevTools 工具。登记前不会启动浏览器。", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
  { name: "browser_call", description: "调用 browser_tools 返回的工具，arguments 必须指定本次授权的 identity_id。", inputSchema: { type: "object", additionalProperties: false, properties: {
    name: { type: "string" }, arguments: { type: "object" },
  }, required: ["name", "arguments"] } },
];

export function resolveEnvironment(authorization, input) {
  check(authorization.environment_input === "AGENT_PROMPT" && authorization.environment_ready === false && authorization.status === "AUTHORIZED", "runtime-environment-already-prepared");
  check(input && Object.keys(input).every(key => ["target_url", "origins", "identities", "sensitive_values", "test_data_scope", "cleanup_instructions"].includes(key)), "runtime-environment-plan-invalid");
  const target = httpUrl(input.target_url);
  check(target && Array.isArray(input.origins) && input.origins.length > 0 && input.origins.length <= 8
    && input.origins.every(origin => httpUrl(origin)?.origin === origin) && input.origins.includes(target.origin), "runtime-environment-origins-invalid");
  check(Array.isArray(input.identities) && input.identities.length > 0 && input.identities.length <= 8
    && input.identities.every(identity => identity && Object.keys(identity).every(key => ["id", "role"].includes(key)) && ID.test(identity.id ?? "") && ["anonymous", "test-user"].includes(identity.role))
    && new Set(input.identities.map(identity => identity.id)).size === input.identities.length, "runtime-environment-identities-invalid");
  check(Array.isArray(input.sensitive_values) && input.sensitive_values.every(text), "runtime-environment-redactions-invalid");
  check(input.identities.every(identity => !input.sensitive_values.includes(identity.id)), "runtime-environment-identity-must-not-contain-credentials");
  const identities = input.identities.map(identity => ({ ...identity, tenant: null }));
  if (authorization.identity_preference === "anonymous") check(identities.every(identity => identity.role === "anonymous"), "runtime-identity-not-authorized");
  // Keep the interpretation private; packets bind an opaque scope ID, never the
  // user's original text or credentials. Missing mutation details restrict only
  // mutation packets, not environment contact or normal login.
  const scope = text(input.test_data_scope) && text(input.cleanup_instructions) ? `environment-scope:${authorization.context_digest}` : null;
  return { public: seal({ ...authorization, environment_ready: true, input_authorization_digest: authorization.artifact_digest,
    origins: [...new Set(input.origins)].sort(), identities, test_data_scope: scope }),
    private: { environment_ready: true, target_url: target.href, sensitive_values: [...new Set(input.sensitive_values)],
      test_data_scope: input.test_data_scope ?? "", cleanup_instructions: input.cleanup_instructions ?? "" } };
}

export function workerInput(packet, authorization, privateContext) {
  return { packet, authorization, environment: privateContext };
}
