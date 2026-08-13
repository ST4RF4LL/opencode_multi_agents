import { createHash } from "node:crypto";
import { findingObjectDigest } from "../../skills/common-subagent/finding-evidence-contract/scripts/finding-contract.mjs";
import { buildExternalRuntimeValidationRequest } from "../../skills/common-subagent/finding-evidence-contract/scripts/external-runtime-validation-contract.mjs";
import { stageEnvelopeDigest } from "../../skills/common-subagent/audit-artifact-management/scripts/stage-agent-contract.mjs";

const DIGEST = "a".repeat(64);
const SOURCE_DIGEST = "b".repeat(64);

export function buildWebXssRuntimeRequest(commit, { auditId = "web-xss-fixture" } = {}) {
  const finding = {
    finding_schema_version: 2,
    finding_id: "FIND-WEB-XSS-001",
    audit_id: auditId,
    scope_digest: DIGEST,
    state: "CANDIDATE",
    classification: {
      vulnerability_type_id: "JW-INJECT-06",
      origin_lens: "sink-driven",
      discovery_track: "coverage",
      dimension_claims: [{ dimension: "D5", rationale: "Untrusted profile text reaches an HTML rendering sink." }],
    },
    routing: { focus_area_id: "FA-WEB", primary_check_id: "check:web-xss", domain: "web", threat_ids: ["T-XSS"] },
    locations: { primary: { file: "public/app.js", line_start: 42, source_digest: SOURCE_DIGEST } },
    evidence: {
      facts: [{
        kind: "source",
        claim: "An authorized test user controls the profile display name.",
        locator: { file: "public/app.js", line_start: 38, source_digest: SOURCE_DIGEST },
        method: "fixture",
        source_digest: SOURCE_DIGEST,
        confidence: "high",
      }, {
        kind: "sink",
        claim: "The display name reaches innerHTML without output encoding.",
        locator: { file: "public/app.js", line_start: 42, source_digest: SOURCE_DIGEST },
        method: "fixture",
        source_digest: SOURCE_DIGEST,
        confidence: "high",
      }],
    },
    reachability: { state: "static-reachable" },
    attacker_influence: { state: "direct" },
    attack_surface: {
      schema_version: 1,
      in_scope: { state: "YES", rationale: "The browser source is frozen in scope.", evidence_fact_indexes: [0, 1] },
      exposure: { state: "AUTHENTICATED", surface: "Profile update UI", rationale: "A test user controls the rendered field.", evidence_fact_indexes: [0] },
      vector: { state: "NETWORK", rationale: "The value is submitted and rendered through the Web application.", evidence_fact_indexes: [0, 1] },
      auth_scope: { state: "AUTHENTICATED", rationale: "The profile route requires an account.", evidence_fact_indexes: [0] },
      preconditions: [{ precondition_id: "PRE-XSS", description: "The authorized loopback fixture is running.", feasibility: "UNPROVEN", evidence_fact_indexes: [] }],
      identities: { attacker: "authorized attacker test account", victim: "authorized victim test account", effective_principal: "browser user", evidence_fact_indexes: [0, 1] },
      boundary_crossing: { state: "PROVEN", from: "profile input", to: "innerHTML", rationale: "Static source-to-sink flow is present.", evidence_fact_indexes: [0, 1] },
      impact: { types: ["CONFIDENTIALITY", "INTEGRITY"], outcome: "Attacker-controlled HTML may execute in another test browser context.", evidence_fact_indexes: [1] },
      target_reach: { state: "SINGLE_SERVICE", rationale: "One loopback application is in scope.", evidence_fact_indexes: [1] },
      controls: [],
      counterevidence: [],
      blindspots: ["Persistence and cross-user execution require runtime proof."],
      confidence: { level: "medium", rationale: "Static flow is proven; browser execution is not." },
    },
    guards: [],
    contradictions: [],
    uncertainty: { level: "medium", assumptions: ["The loopback fixture matches the reviewed source."] },
    severity: { rationale: "Cross-user runtime impact remains unverified." },
    remediation: { summary: "Use context-appropriate output encoding and avoid innerHTML." },
    provenance: { source_report_sha256: "c".repeat(64) },
  };
  return buildExternalRuntimeValidationRequest({
    requestId: "RVR-WEB-XSS-001",
    finding,
    findingArtifact: { path: "reports/findings/FIND-WEB-XSS-001.json", sha256: "d".repeat(64) },
    decision: {
      finding_id: finding.finding_id,
      finding_object_digest: findingObjectDigest(finding),
      state: "SUPPORTED_STATIC",
      decision_rationale: "The profile value reaches innerHTML without output encoding.",
      semantic_proof: { source_fact_indexes: [0], sink_or_config_fact_indexes: [1], security_effect: { rationale: "Application-rendered script could execute in a test browser." } },
      blocking_questions: [],
    },
    adjudication: { path: "reports/adjudication/web-xss.json", sha256: "e".repeat(64), json_pointer: "/decisions/0" },
    repository: { repository_id: "fixture", commit },
    policy: {
      target_class: "ISOLATED_TEST_ENVIRONMENT",
      allowed_methods: ["BROWSER_TEST"],
      forbidden_actions: ["PRODUCTION_TARGET", "THIRD_PARTY_TARGET", "REAL_CREDENTIAL_USE", "PERSISTENCE", "DATA_DESTRUCTION"],
      safety_constraints: ["Use only loopback and two synthetic test accounts."],
      network_access: "LOOPBACK_ONLY",
      credentials: "SYNTHETIC_ONLY",
    },
    proofGaps: ["Runtime execution, refresh persistence, cross-user execution, and cleanup are unproven."],
    exportedBySessionId: "orchestrator-web-xss-r1",
  });
}

export function buildWebXssInputEnvelope({ request, requestPath, requestBytes }) {
  const envelope = {
    schema_version: 1,
    contract_id: "P08_RUNTIME_VALIDATION.dynamic-vulnerability-validator",
    stage_id: "P08_RUNTIME_VALIDATION",
    direction: "INPUT",
    audit_id: request.audit_id,
    round: 1,
    agent_name: "dynamic-vulnerability-validator",
    agent_session_id: "dynamic-web-xss-fixture-r1",
    scope_binding: { state: "FROZEN", scope_digest: request.scope_digest },
    artifact_bindings: [{
      artifact_type: "external-runtime-validation-request",
      path: requestPath,
      sha256: createHash("sha256").update(requestBytes).digest("hex"),
      media_type: "application/json",
      json_pointer: null,
    }],
    payload: {
      explicit_user_request: true,
      localhost_target: "http://127.0.0.1:8080",
      attacker_account_supplied: true,
      victim_account_supplied: true,
      login_instructions_supplied: true,
      cleanup_instructions_supplied: true,
    },
    constraints: [],
  };
  envelope.envelope_digest = stageEnvelopeDigest(envelope);
  return envelope;
}
