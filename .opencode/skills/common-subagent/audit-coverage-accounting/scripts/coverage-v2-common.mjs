import { createHash } from "node:crypto";

export const LENSES = ["sink-driven", "control-driven", "config-driven"];
export const DIMENSIONS = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);
export const APPLICABILITY_STATES = ["REQUIRED", "NOT_APPLICABLE", "UNKNOWN"];
export const EXECUTION_STATES = ["PLANNED", "INSPECTED", "VERIFIED", "GAP", "INVALIDATED"];
export const RESULT_STATES = ["NO_FINDING", "FINDING", "INCONCLUSIVE"];
export const DOMAIN_AGENTS = {
  java: "java-source-auditor",
  web: "web-source-auditor",
  platform: "platform-security-auditor",
  "c-cpp": "c-cpp-source-auditor",
  python: "python-source-auditor",
  ai: "ai-security-auditor",
};

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function objectDigest(value, omitted = ["manifest_digest"]) {
  const copy = structuredClone(value);
  for (const field of omitted) delete copy[field];
  return sha256(JSON.stringify(copy));
}

export function exactArray(value, expected) {
  return Array.isArray(value)
    && value.length === expected.length
    && new Set(value).size === value.length
    && expected.every(item => value.includes(item));
}

export function entryAppliesToDomain(entry, domain, catalog) {
  const selector = catalog.coverage_model?.domain_profiles?.[domain]?.entry_selector;
  if (!selector) return false;
  if (selector.kind === "applies_to") return entry.applies_to?.includes(selector.value) === true;
  if (selector.kind === "id-prefix") return entry.id?.startsWith(selector.value) === true;
  return false;
}

export function activeDomains(scope) {
  const owners = new Set((scope.files ?? []).filter(file => file.review_required).map(file => file.owner_agent));
  const domains = Object.entries(DOMAIN_AGENTS)
    .filter(([domain, agent]) => domain === "ai" || owners.has(agent))
    .map(([domain]) => domain);
  return domains.sort();
}

export function interfaceDomains(item) {
  const base = Object.entries(DOMAIN_AGENTS).find(([domain, agent]) => domain !== "ai" && agent === item.owner_agent)?.[0];
  return [...new Set([base, "ai"].filter(Boolean))].sort();
}

export function coverageCheckId(subjectKind, subjectId, vulnerabilityTypeId, domain, lens) {
  return `check:${sha256([subjectKind, subjectId, vulnerabilityTypeId, domain, lens].join("\n")).slice(0, 32)}`;
}

export function validateCatalogV2(catalog) {
  const errors = [];
  if (catalog?.schema_version !== 2) errors.push("schema_version must be 2");
  if (typeof catalog?.profile_id !== "string" || !catalog.profile_id.endsWith("-v4")) errors.push("profile_id must identify v4");
  if (!exactArray(catalog?.required_lenses, LENSES)) errors.push("required_lenses must contain the three canonical lenses");
  const model = catalog?.coverage_model;
  if (!model || typeof model !== "object") errors.push("coverage_model is required");
  if (!exactArray(model?.applicability_states, APPLICABILITY_STATES)) errors.push("invalid applicability states");
  if (!exactArray(model?.execution_states, EXECUTION_STATES)) errors.push("invalid execution states");
  if (!exactArray(model?.result_states, RESULT_STATES)) errors.push("invalid result states");
  if (!exactArray(model?.target_kinds, ["catalog-domain", "interface"])) errors.push("invalid target kinds");
  for (const [domain, agent] of Object.entries(DOMAIN_AGENTS)) {
    const selector = model?.domain_profiles?.[domain]?.entry_selector;
    if (!selector || !["applies_to", "id-prefix"].includes(selector.kind) || typeof selector.value !== "string") {
      errors.push(`invalid domain selector: ${domain}/${agent}`);
    }
  }
  if (model?.selectors?.["catalog-domain"]?.applicability !== "REQUIRED"
    || model?.selectors?.["catalog-domain"]?.negative_discovery_required !== true) {
    errors.push("catalog-domain selector must require negative discovery");
  }
  const ids = new Set();
  if (!Array.isArray(catalog?.entries) || catalog.entries.length === 0) errors.push("entries must be non-empty");
  for (const entry of catalog?.entries ?? []) {
    if (typeof entry.id !== "string" || !/^(?:JW|AI)-[A-Z0-9-]+$/.test(entry.id)) errors.push(`invalid entry id: ${entry.id}`);
    if (ids.has(entry.id)) errors.push(`duplicate entry id: ${entry.id}`);
    ids.add(entry.id);
    if (!exactArray(entry.dimensions, [...new Set(entry.dimensions ?? [])])
      || entry.dimensions.some(dimension => !DIMENSIONS.includes(dimension))) errors.push(`invalid dimensions: ${entry.id}`);
    if (!Array.isArray(entry.applies_to) || entry.applies_to.length === 0) errors.push(`missing applies_to: ${entry.id}`);
    for (const lens of LENSES) {
      const questionField = model?.evidence_contracts?.[lens]?.decision_question_field;
      if (!questionField || typeof entry[questionField] !== "string" || entry[questionField].trim() === "") {
        errors.push(`missing ${lens} question: ${entry.id}`);
      }
      if (!exactArray(model?.evidence_contracts?.[lens]?.required_receipt_fields, ["source_hashes", "locators", "query_or_rule", "tool", "result_digest"])) {
        errors.push(`invalid evidence contract: ${lens}`);
      }
    }
  }
  for (const domain of Object.keys(DOMAIN_AGENTS)) {
    if (!(catalog?.entries ?? []).some(entry => entryAppliesToDomain(entry, domain, catalog))) errors.push(`domain has no applicable entries: ${domain}`);
  }
  return [...new Set(errors)];
}

export function validatePlan(plan) {
  const errors = [];
  if (plan?.schema_version !== 2) errors.push("plan schema_version must be 2");
  if (!Array.isArray(plan?.checks) || plan.checks.length === 0) errors.push("plan checks must be non-empty");
  const checkIds = new Set();
  const lensGroups = new Map();
  for (const check of plan?.checks ?? []) {
    const expectedId = coverageCheckId(check.subject_kind, check.subject_id, check.vulnerability_type_id, check.domain, check.lens);
    if (check.check_id !== expectedId) errors.push(`invalid check id: ${check.check_id}`);
    if (checkIds.has(check.check_id)) errors.push(`duplicate check id: ${check.check_id}`);
    checkIds.add(check.check_id);
    if (!["catalog-domain", "interface"].includes(check.subject_kind)) errors.push(`invalid subject kind: ${check.check_id}`);
    if (!APPLICABILITY_STATES.includes(check.applicability)) errors.push(`invalid applicability: ${check.check_id}`);
    if (!LENSES.includes(check.lens)) errors.push(`invalid lens: ${check.check_id}`);
    if (typeof check.focus_area_id !== "string" || check.focus_area_id.trim() === "") errors.push(`focus area binding missing: ${check.check_id}`);
    if (check.applicability === "NOT_APPLICABLE" && typeof check.applicability_reason !== "string") errors.push(`N/A reason missing: ${check.check_id}`);
    if (check.subject_kind === "catalog-domain" && check.applicability !== "REQUIRED") errors.push(`catalog-domain must be required: ${check.check_id}`);
    if (check.subject_kind === "catalog-domain" && check.negative_discovery_required !== true) errors.push(`negative discovery missing: ${check.check_id}`);
    if (check.applicability === "REQUIRED"
      && (!Array.isArray(check.required_source_file_ids) || check.required_source_file_ids.length === 0
        || new Set(check.required_source_file_ids).size !== check.required_source_file_ids.length)) {
      errors.push(`required source universe missing or duplicated: ${check.check_id}`);
    }
    const groupKey = [check.subject_kind, check.subject_id, check.vulnerability_type_id, check.domain].join("|");
    const group = lensGroups.get(groupKey) ?? [];
    group.push(check.lens);
    lensGroups.set(groupKey, group);
  }
  for (const [key, lenses] of lensGroups) if (!exactArray(lenses, LENSES)) errors.push(`tri-lens group incomplete: ${key}`);
  const counts = Object.fromEntries(APPLICABILITY_STATES.map(state => [
    state,
    (plan?.checks ?? []).filter(check => check.applicability === state).length,
  ]));
  if (!exactArray(plan?.required_lenses, LENSES)) errors.push("plan required_lenses must contain the three canonical lenses");
  if (plan?.summary?.atomic_checks !== (plan?.checks?.length ?? 0)) errors.push("plan atomic check count mismatch");
  if (plan?.summary?.required !== counts.REQUIRED) errors.push("plan required count mismatch");
  if (plan?.summary?.not_applicable !== counts.NOT_APPLICABLE) errors.push("plan N/A count mismatch");
  if (plan?.summary?.unknown !== counts.UNKNOWN) errors.push("plan unknown count mismatch");
  if (plan?.complete !== (counts.UNKNOWN === 0)) errors.push("plan completeness mismatch");
  const sourceIds = new Set((plan?.source_index ?? []).map(source => source.file_id));
  for (const check of plan?.checks ?? []) {
    if (check.applicability === "REQUIRED" && (check.required_source_file_ids ?? []).some(fileId => !sourceIds.has(fileId))) {
      errors.push(`required source is outside frozen source index: ${check.check_id}`);
    }
  }
  if (plan?.manifest_digest !== objectDigest(plan)) errors.push("plan manifest digest mismatch");
  return [...new Set(errors)];
}
