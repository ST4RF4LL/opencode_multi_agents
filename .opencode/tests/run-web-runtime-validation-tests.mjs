#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runtimeValidationPacketDigest } from "../skills/common-subagent/finding-evidence-contract/scripts/external-runtime-validation-contract.mjs";
import {
  validateGenericWebRuntimeResult,
  validateWebTargetBinding,
  webTargetBindingDigest,
} from "../skills/dynamic-vulnerability-validator-subagent/web-runtime-validation/scripts/validate-web-runtime-result.mjs";
import { buildWebXssRuntimeRequest } from "./fixtures/web-xss-runtime-fixture.mjs";
import { listValidationRequests } from "../web/dynamic-validation-observatory/model.mjs";
import { webValidationCapability, webValidationTypes } from "../web/dynamic-validation-observatory/web-validation-policy.mjs";

const request = buildWebXssRuntimeRequest("0123456789abcdef");
request.claim.vulnerability_type_id = "JW-INJECT-04";
request.packet_digest = runtimeValidationPacketDigest(request);

const target = {
  schema_version: 1,
  binding_type: "WEB_LOCALHOST_TARGET",
  request_id: request.request_id,
  audit_id: request.audit_id,
  finding_id: request.finding_id,
  vulnerability_type_id: request.claim.vulnerability_type_id,
  authorization: { explicit_dynamic_validation_request: true, provided_by_user_prompt: true },
  target: { base_url: "http://127.0.0.1:8080/template", allowed_origins: ["http://127.0.0.1:8080"] },
  accounts: { attacker_role: "attacker", victim_role: "victim", distinct_test_accounts: true },
  cleanup: { mode: "ATTEMPT_AND_REPORT", instructions_provided: true },
};
target.binding_digest = webTargetBindingDigest(target);

const result = {
  schema_version: 1,
  packet_type: "EXTERNAL_RUNTIME_VALIDATION_RESULT",
  request_id: request.request_id,
  request_packet_digest: request.packet_digest,
  audit_id: request.audit_id,
  scope_digest: request.scope_digest,
  finding_id: request.finding_id,
  finding_object_digest: request.finding_object_digest,
  validator: { project: "dynamic-vulnerability-validator", version: "1.0.0", session_id: "fixture-session" },
  outcome: "INCONCLUSIVE",
  methods: [],
  observations: [],
  evidence_artifacts: [],
  counterevidence: [],
  residual_gaps: ["确认代码执行需要被策略禁止的破坏性动作。"],
  safety_attestation: {
    isolated_test_environment: true,
    production_targets_contacted: false,
    third_party_targets_contacted: false,
    real_credentials_used: false,
    destructive_actions_performed: false,
    notes: ["仅检查了安全边界。"],
  },
  environment_binding_digest: target.binding_digest,
  browser_backend: {
    name: "chrome-devtools-mcp",
    package: "chrome-devtools-mcp@1.8.0",
    resolved_version: "fixture",
    headless: false,
    isolated: true,
  },
};
result.packet_digest = runtimeValidationPacketDigest(result);

assert.equal((await webValidationTypes()).length > 1, true);
assert.equal((await webValidationCapability("JW-INJECT-06")).validator, "web-xss");
assert.equal((await webValidationCapability("JW-INJECT-04")).validator, "web-generic");
assert.equal((await webValidationCapability("JW-ERROR-01")).validator, "web-generic");
assert.equal((await webValidationCapability("JW-RESILIENCE-01")).validator, "web-generic");
assert.equal(await webValidationCapability("JW-INJECT-03"), null);
assert.deepEqual(validateWebTargetBinding(target, request), []);
assert.deepEqual(validateGenericWebRuntimeResult(result, target, request), []);
const anonymousTarget = structuredClone(target);
anonymousTarget.accounts.distinct_test_accounts = false;
anonymousTarget.cleanup.instructions_provided = false;
anonymousTarget.binding_digest = webTargetBindingDigest(anonymousTarget);
assert.deepEqual(validateWebTargetBinding(anonymousTarget, request), []);

const temp = await mkdtemp(join(tmpdir(), "web-runtime-validation-"));
try {
  const auditRoot = join(temp, request.audit_id);
  await mkdir(auditRoot, { recursive: true });
  await writeFile(join(auditRoot, "request.json"), `${JSON.stringify(request)}\n`, "utf8");
  await writeFile(join(auditRoot, "envelope-input.json"), "{}\n", "utf8");
  const [descriptor] = await listValidationRequests(temp);
  assert.equal(descriptor.validation_type_supported, true);
  assert.equal(descriptor.validator, "web-generic");
  assert.deepEqual(descriptor.dispatch_blockers, []);
  assert.equal(descriptor.dispatch_ready, true);
} finally {
  await rm(temp, { recursive: true, force: true });
}

process.stdout.write(`${JSON.stringify({ complete: true, validator: "web-generic", cases: 13 })}\n`);
