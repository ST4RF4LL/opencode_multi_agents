#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import {
  targetBindingDigest,
  validateLocalhostTargetBinding,
  validateNetworkTraceMetadata,
  validateSanitizedHttpExchange,
  validateWebXssRuntimeResult,
} from "../skills/dynamic-vulnerability-validator-subagent/web-xss-runtime-validation/scripts/validate-web-xss-runtime-result.mjs";

const REQUEST = {
  request_id: "RVR-XSS-001",
  audit_id: "dynamic-xss-fixture",
  finding_id: "FIND-XSS-001",
};

function target(overrides = {}) {
  const value = {
    schema_version: 1,
    binding_type: "WEB_XSS_LOCALHOST_TARGET",
    request_id: REQUEST.request_id,
    audit_id: REQUEST.audit_id,
    finding_id: REQUEST.finding_id,
    authorization: {
      explicit_dynamic_validation_request: true,
      provided_by_user_prompt: true,
    },
    target: {
      base_url: "http://127.0.0.1:8080/comments",
      allowed_origins: ["http://127.0.0.1:8080"],
    },
    accounts: {
      attacker_role: "attacker",
      victim_role: "victim",
      distinct_test_accounts: true,
    },
    login: {
      instructions_source: "user-prompt",
      credentials_source: "user-prompt",
    },
    cleanup: {
      mode: "ATTEMPT_AND_REPORT",
      instructions_provided: true,
    },
    ...overrides,
  };
  value.binding_digest = targetBindingDigest(value);
  return value;
}

function result(level = "STORED_CROSS_USER") {
  return {
    web_xss_extension_schema_version: 2,
    outcome: "SUPPORTED_RUNTIME",
    residual_gaps: [],
    evidence_artifacts: [
      {
        artifact_id: "ev-http-001",
        path: "/fixture/http-001.json",
        sha256: "a".repeat(64),
        kind: "sanitized-http-exchange",
        media_type: "application/json",
        sanitized: true,
      },
    ],
    environment_binding_digest: target().binding_digest,
    browser_backend: {
      name: "chrome-devtools-mcp",
      package: "chrome-devtools-mcp@latest",
      resolved_version: "test-version",
      headless: false,
      isolated: true,
    },
    xss_verification: {
      level,
      preferred_goal_met: level === "STORED_CROSS_USER",
      proof_id: "XSS-PROOF-001",
      dom_probe_used: false,
      app_input_submitted: true,
      application_execution_observed: true,
      reload_or_revisit_completed: true,
      execution_after_reload: true,
      attacker_context_id: "attacker-context",
      victim_context_id: "victim-context",
      distinct_test_accounts: true,
      victim_execution_observed: true,
      cleanup: {
        attempted: true,
        status: "SUCCEEDED",
        still_executable: false,
        details: "Removed and verified after refresh.",
      },
    },
    network_trace: {
      schema_version: 1,
      capture_source: "chrome-devtools-mcp",
      completeness: "KEY_EXCHANGES",
      sensitive_headers_redacted: true,
      exchanges: [
        {
          exchange_id: "http-001",
          artifact_id: "ev-http-001",
          sequence: 1,
          phase: "APP_INPUT_SUBMISSION",
          step_id: "submit-marker",
        },
      ],
    },
  };
}

function body(text, mediaType = "application/json") {
  return {
    media_type: mediaType,
    text,
    sha256: createHash("sha256").update(text).digest("hex"),
    truncated: false,
  };
}

function exchange() {
  return {
    schema_version: 1,
    artifact_type: "SANITIZED_HTTP_EXCHANGE",
    exchange_id: "http-001",
    sequence: 1,
    phase: "APP_INPUT_SUBMISSION",
    step_id: "submit-marker",
    started_at: "2026-08-08T14:32:06.000Z",
    duration_ms: 184,
    browser_context_id: "attacker-context",
    request: {
      method: "POST",
      url: "http://127.0.0.1:8080/api/profile",
      headers: [
        { name: "Content-Type", value: "application/json" },
        { name: "Authorization", value: "[REDACTED]" },
      ],
      body: body('{"marker":"XSS-PROOF-001"}'),
    },
    response: {
      status: 200,
      status_text: "OK",
      headers: [{ name: "Content-Type", value: "application/json" }],
      body: body('{"updated":true}'),
      error: null,
    },
    capture: {
      source: "chrome-devtools-mcp",
      request_id: "cdp-request-001",
      sanitized: true,
    },
  };
}

function has(errors, expected) {
  assert(errors.includes(expected), `Expected ${expected}; got ${errors.join(", ")}`);
}

const validTarget = target();
assert.deepEqual(validateLocalhostTargetBinding(validTarget, REQUEST), []);
assert.deepEqual(validateWebXssRuntimeResult(result(), validTarget), []);
assert.deepEqual(validateNetworkTraceMetadata(result()), []);
assert.deepEqual(validateSanitizedHttpExchange(exchange(), validTarget), []);

const remote = target({ target: { base_url: "https://example.com", allowed_origins: ["https://example.com"] } });
has(validateLocalhostTargetBinding(remote, REQUEST), "web-xss-target-base-url-not-loopback");

const secretBearing = target({ password: "must-not-be-persisted" });
has(validateLocalhostTargetBinding(secretBearing, REQUEST), "web-xss-target-secret-shaped-field-forbidden");

const domOnly = result("DOM_PROBE_ONLY");
domOnly.xss_verification.preferred_goal_met = false;
has(validateWebXssRuntimeResult(domOnly, validTarget), "web-xss-result-dom-probe-cannot-support-runtime");

const missingReload = result("STORED_SAME_USER");
missingReload.xss_verification.preferred_goal_met = false;
missingReload.xss_verification.reload_or_revisit_completed = false;
missingReload.xss_verification.execution_after_reload = false;
has(validateWebXssRuntimeResult(missingReload, validTarget), "web-xss-result-stored-proof-missing");

const sharedContext = result();
sharedContext.xss_verification.victim_context_id = sharedContext.xss_verification.attacker_context_id;
has(validateWebXssRuntimeResult(sharedContext, validTarget), "web-xss-result-contexts-not-distinct");

const cleanupFailed = result();
cleanupFailed.xss_verification.cleanup = {
  attempted: true,
  status: "FAILED",
  still_executable: true,
  details: "Delete returned success but the marker still executed after refresh.",
};
has(validateWebXssRuntimeResult(cleanupFailed, validTarget), "web-xss-result-cleanup-failure-gap-missing");
cleanupFailed.residual_gaps = ["Stored payload cleanup failed; manual removal is required."];
assert.deepEqual(validateWebXssRuntimeResult(cleanupFailed, validTarget), []);

const missingTrace = result();
delete missingTrace.network_trace;
has(validateWebXssRuntimeResult(missingTrace, validTarget), "web-xss-result-network-trace-invalid");

const remoteExchange = exchange();
remoteExchange.request.url = "https://example.com/api/profile";
has(validateSanitizedHttpExchange(remoteExchange, validTarget), "web-xss-http-exchange-request-invalid");

const rawAuthorization = exchange();
rawAuthorization.request.headers[1].value = "Bearer secret-value";
has(validateSanitizedHttpExchange(rawAuthorization, validTarget), "web-xss-http-exchange-request-invalid");

const secretBody = exchange();
secretBody.request.body = body('{"password":"plain-text"}');
has(validateSanitizedHttpExchange(secretBody, validTarget), "web-xss-http-exchange-request-invalid");

process.stdout.write(`${JSON.stringify({ complete: true, validator: "web-xss", cases: 13 })}\n`);
