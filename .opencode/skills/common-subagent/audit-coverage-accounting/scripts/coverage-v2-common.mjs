import { createHash } from "node:crypto";

export const LENSES = ["sink-driven", "control-driven", "config-driven"];
export const DIMENSIONS = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);
export const APPLICABILITY_STATES = ["REQUIRED", "NOT_APPLICABLE", "UNKNOWN"];
export const EXECUTION_STATES = ["PLANNED", "INSPECTED", "VERIFIED", "GAP", "INVALIDATED"];
export const RESULT_STATES = ["NO_FINDING", "FINDING", "INCONCLUSIVE"];
export const COVERAGE_MODEL_VERSION = "coverage-v3";
export const PLAN_SCHEMA_VERSION = 3;
export const COVERAGE_EXECUTION_MODEL = "assignment-unit-v1";
export const COVERAGE_POLICY_MODES = ["observe", "release", "assurance"];
export const DOMAIN_AGENTS = {
  java: "java-source-auditor",
  web: "web-source-auditor",
  platform: "platform-security-auditor",
  "c-cpp": "c-cpp-source-auditor",
  python: "python-source-auditor",
  ai: "ai-security-auditor",
};

export function functionManifestMembership(scope, manifests) {
  const membership = new Map();
  for (const manifest of manifests ?? []) {
    for (const path of manifest.expected_files ?? []) membership.set(path, (membership.get(path) ?? 0) + 1);
  }
  const missing = (scope.files ?? []).filter(file => file.function_inventory_required && membership.get(file.path) !== 1);
  return {
    membership,
    missing,
    duplicates: [...membership.entries()].filter(([, count]) => count > 1).map(([path]) => path).sort(),
  };
}

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

export function interfaceApplicability(entry, domain, item, catalog) {
  const profile = catalog.coverage_model?.interface_applicability_profile;
  for (const rule of profile?.rules ?? []) {
    if (!rule.domains.includes(domain)
      || !rule.interface_kinds.includes(item.kind)
      || !rule.directions.includes(item.direction)) continue;
    const exactMatch = rule.vulnerability_type_ids?.includes(entry.id) === true;
    const prefixMatch = rule.vulnerability_type_prefixes?.some(prefix => entry.id.startsWith(prefix)) === true;
    if (!exactMatch && !prefixMatch) continue;
    return {
      applicability: "REQUIRED",
      reason: `explicit-interface-rule:${profile.profile_id}:${rule.rule_id}`,
      rule_id: rule.rule_id,
    };
  }
  return {
    applicability: profile?.default_applicability ?? "UNKNOWN",
    reason: `no-explicit-interface-rule:${profile?.profile_id ?? "missing-profile"}`,
    rule_id: null,
  };
}

export function activeDomains(scope) {
  const owners = new Set((scope.files ?? []).filter(file => file.review_required).map(file => file.owner_agent));
  const domains = Object.entries(DOMAIN_AGENTS)
    .filter(([domain, agent]) => domain === "ai" || owners.has(agent))
    .map(([domain]) => domain);
  return domains.sort();
}

export function validateFocusAreaPartition({ scope, functionManifests, catalog, focusAreas }) {
  const errors = [];
  const expected = new Set();
  const observed = new Set();
  const catalogEntries = new Map((catalog.entries ?? []).map(entry => [entry.id, entry]));
  const domains = activeDomains(scope);
  const addExpected = (agent, domain, kind, id) => expected.add(`${agent}|${domain}|${kind}|${id}`);
  const addObserved = (agent, domain, kind, id, assignmentId) => {
    const key = `${agent}|${domain}|${kind}|${id}`;
    if (observed.has(key)) errors.push(`duplicate primary ${kind} assignment: ${key}`);
    observed.add(key);
    if (!expected.has(key)) errors.push(`assignment outside frozen universe (${assignmentId}): ${key}`);
  };

  for (const file of scope.files ?? []) {
    if (!file.review_required) continue;
    addExpected(file.owner_agent, "base", "file", file.file_id);
    addExpected(DOMAIN_AGENTS.ai, "ai", "file", file.file_id);
  }
  for (const fn of (functionManifests ?? []).flatMap(manifest => manifest.functions ?? [])) {
    addExpected(fn.owner_agent, "base", "function", fn.function_id);
    addExpected(DOMAIN_AGENTS.ai, "ai", "function", fn.function_id);
  }
  for (const domain of domains) {
    for (const entry of catalog.entries ?? []) {
      if (entryAppliesToDomain(entry, domain, catalog)) addExpected(DOMAIN_AGENTS[domain], domain, "catalog", entry.id);
    }
  }

  for (const focus of focusAreas.focus_areas ?? []) {
    const focusId = focus.focus_area_id ?? "unknown-focus";
    if (!Array.isArray(focus.assignments) || focus.assignments.length === 0) {
      errors.push(`Focus Area has no assignments: ${focusId}`);
      continue;
    }
    for (const assignment of focus.assignments) {
      const assignmentId = assignment.assignment_id ?? `${focusId}:unknown-assignment`;
      for (const field of ["file_ids", "function_ids", "catalog_ids"]) {
        if (!Array.isArray(assignment[field]) || new Set(assignment[field]).size !== assignment[field].length) {
          errors.push(`invalid ${field} in ${assignmentId}`);
        }
      }
      const fileFunctionDomain = assignment.file_function_domain;
      if (!['base', 'ai'].includes(fileFunctionDomain)) errors.push(`invalid file_function_domain in ${assignmentId}`);
      if (!Object.hasOwn(DOMAIN_AGENTS, assignment.language)) errors.push(`invalid language in ${assignmentId}: ${assignment.language ?? "missing"}`);
      else if (assignment.agent_name !== DOMAIN_AGENTS[assignment.language]) errors.push(`agent/language mismatch in ${assignmentId}: ${assignment.agent_name}|${assignment.language}`);
      for (const fileId of assignment.file_ids ?? []) addObserved(assignment.agent_name, fileFunctionDomain, "file", fileId, assignmentId);
      for (const functionId of assignment.function_ids ?? []) addObserved(assignment.agent_name, fileFunctionDomain, "function", functionId, assignmentId);

      if ((assignment.catalog_ids?.length ?? 0) > 0) {
        const domain = assignment.catalog_domain;
        if (!Object.hasOwn(DOMAIN_AGENTS, domain)) {
          errors.push(`invalid catalog_domain in ${assignmentId}: ${domain ?? "missing"}`);
          continue;
        }
        if (assignment.agent_name !== DOMAIN_AGENTS[domain]) {
          errors.push(`catalog agent/domain mismatch in ${assignmentId}: ${assignment.agent_name}|${domain}`);
        }
        if (assignment.language !== domain) errors.push(`catalog language/domain mismatch in ${assignmentId}: ${assignment.language}|${domain}`);
        for (const catalogId of assignment.catalog_ids) {
          if (!catalogEntries.has(catalogId)) errors.push(`unknown catalog ID in ${assignmentId}: ${catalogId}`);
          addObserved(assignment.agent_name, domain, "catalog", catalogId, assignmentId);
        }
      }
    }
  }

  for (const key of expected) if (!observed.has(key)) errors.push(`missing primary assignment: ${key}`);
  return [...new Set(errors)].sort();
}

export function interfaceDomains(item) {
  const base = Object.entries(DOMAIN_AGENTS).find(([domain, agent]) => domain !== "ai" && agent === item.owner_agent)?.[0];
  return [...new Set([base, "ai"].filter(Boolean))].sort();
}

export function coverageCheckId(subjectKind, subjectId, vulnerabilityTypeId, domain, lens) {
  return `check:${sha256([subjectKind, subjectId, vulnerabilityTypeId, domain, lens].join("\n")).slice(0, 32)}`;
}

export function interfaceGroupId(focusAreaId, domain, vulnerabilityTypeId, interfaceIds) {
  const canonical = [...new Set(interfaceIds ?? [])].sort();
  return `interface-group:${sha256(JSON.stringify([
    focusAreaId,
    domain,
    vulnerabilityTypeId,
    canonical,
  ])).slice(0, 32)}`;
}

export function coverageUnitId(assignmentId, focusAreaId, domain, checkIds) {
  const canonical = [...new Set(checkIds ?? [])].sort();
  return `coverage-unit:${sha256(JSON.stringify([
    assignmentId,
    focusAreaId,
    domain,
    canonical,
  ])).slice(0, 32)}`;
}

export function sourceSetId(fileIds) {
  const canonical = [...fileIds].sort();
  return `source-set:${sha256(JSON.stringify(canonical)).slice(0, 32)}`;
}

export function sourceFileIdsForCheck(plan, check) {
  const sourceSet = (plan.source_sets ?? []).find(item => item.source_set_id === check.required_source_set_id);
  if (!sourceSet) throw new Error(`Coverage check references an unknown source set: ${check.check_id}`);
  return sourceSet.file_ids;
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
  const interfaceProfile = model?.interface_applicability_profile;
  if (interfaceProfile?.schema_version !== 1 || typeof interfaceProfile?.profile_id !== "string"
    || !["NOT_APPLICABLE", "UNKNOWN"].includes(interfaceProfile?.default_applicability)
    || !Array.isArray(interfaceProfile?.rules) || interfaceProfile.rules.length === 0) {
    errors.push("invalid explicit interface applicability profile");
  }
  const ids = new Set();
  if (!Array.isArray(catalog?.entries) || catalog.entries.length === 0) errors.push("entries must be non-empty");
  for (const entry of catalog?.entries ?? []) {
    if (typeof entry.id !== "string" || !/^(?:JW|JAVA|AI)-[A-Z0-9-]+$/.test(entry.id)) errors.push(`invalid entry id: ${entry.id}`);
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
      if (!exactArray(model?.evidence_contracts?.[lens]?.required_receipt_fields, ["source_set_id", "locators", "query_or_rule", "tool", "result_attestation"])) {
        errors.push(`invalid evidence contract: ${lens}`);
      }
    }
  }
  const ruleIds = new Set();
  for (const rule of interfaceProfile?.rules ?? []) {
    if (typeof rule.rule_id !== "string" || ruleIds.has(rule.rule_id)) errors.push(`invalid or duplicate interface rule: ${rule.rule_id}`);
    ruleIds.add(rule.rule_id);
    if (!Array.isArray(rule.domains) || rule.domains.length === 0 || rule.domains.some(domain => !Object.hasOwn(DOMAIN_AGENTS, domain))) {
      errors.push(`invalid interface rule domains: ${rule.rule_id}`);
    }
    if (!Array.isArray(rule.interface_kinds) || rule.interface_kinds.length === 0
      || !Array.isArray(rule.directions) || rule.directions.some(direction => !["ingress", "egress", "bidirectional"].includes(direction))) {
      errors.push(`invalid interface rule selector: ${rule.rule_id}`);
    }
    if ((rule.vulnerability_type_ids?.length ?? 0) + (rule.vulnerability_type_prefixes?.length ?? 0) === 0) {
      errors.push(`interface rule has no vulnerability types: ${rule.rule_id}`);
      continue;
    }
    for (const prefix of rule.vulnerability_type_prefixes ?? []) {
      if (typeof prefix !== "string" || !(catalog.entries ?? []).some(entry => entry.id.startsWith(prefix))) {
        errors.push(`interface rule has invalid vulnerability prefix: ${rule.rule_id}/${prefix}`);
        continue;
      }
      for (const domain of rule.domains ?? []) {
        if (!(catalog.entries ?? []).some(entry => entry.id.startsWith(prefix) && entryAppliesToDomain(entry, domain, catalog))) {
          errors.push(`interface rule prefix/domain mismatch: ${rule.rule_id}/${domain}/${prefix}`);
        }
      }
    }
    for (const id of rule.vulnerability_type_ids ?? []) {
      const entry = catalog.entries?.find(candidate => candidate.id === id);
      if (!entry) errors.push(`interface rule references unknown vulnerability type: ${rule.rule_id}/${id}`);
      for (const domain of rule.domains ?? []) {
        if (entry && !entryAppliesToDomain(entry, domain, catalog)) errors.push(`interface rule/domain mismatch: ${rule.rule_id}/${domain}/${id}`);
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
  if (plan?.schema_version !== PLAN_SCHEMA_VERSION) errors.push(`plan schema_version must be ${PLAN_SCHEMA_VERSION}`);
  if (plan?.coverage_model_version !== COVERAGE_MODEL_VERSION) errors.push(`coverage_model_version must be ${COVERAGE_MODEL_VERSION}`);
  const directRecon = plan?.inputs?.input_mode === "direct-recon";
  if (!directRecon && !/^[a-f0-9]{64}$/.test(plan?.inputs?.snapshot_digest ?? "")) errors.push("plan snapshot binding is missing");
  if (!Array.isArray(plan?.checks) || plan.checks.length === 0) errors.push("plan checks must be non-empty");
  if (!Array.isArray(plan?.source_index) || plan.source_index.length === 0) errors.push("plan source_index must be non-empty");
  const sourceIdList = (plan?.source_index ?? []).map(source => source.file_id);
  const sourceIds = new Set(sourceIdList);
  if (sourceIds.size !== sourceIdList.length) errors.push("plan source_index contains duplicate file IDs");
  if (JSON.stringify(sourceIdList) !== JSON.stringify([...sourceIdList].sort())) errors.push("plan source_index must be sorted by file ID");
  for (const source of plan?.source_index ?? []) {
    if (typeof source.file_id !== "string" || typeof source.path !== "string"
      || !["file", "symlink"].includes(source.type)
      || (source.type === "file" && !/^[a-f0-9]{64}$/.test(source.sha256 ?? ""))
      || (source.type === "symlink" && (source.sha256 !== null || typeof source.link_target !== "string"))) {
      errors.push(`invalid frozen source index row: ${source.file_id ?? "<missing>"}`);
    }
  }
  const sourceSets = new Map();
  for (const sourceSet of plan?.source_sets ?? []) {
    if (!Array.isArray(sourceSet.file_ids) || sourceSet.file_ids.length === 0
      || new Set(sourceSet.file_ids).size !== sourceSet.file_ids.length
      || JSON.stringify(sourceSet.file_ids) !== JSON.stringify([...sourceSet.file_ids].sort())
      || sourceSet.source_set_id !== sourceSetId(sourceSet.file_ids)) {
      errors.push(`invalid source set: ${sourceSet.source_set_id}`);
      continue;
    }
    if (sourceSets.has(sourceSet.source_set_id)) errors.push(`duplicate source set: ${sourceSet.source_set_id}`);
    if (sourceSet.file_ids.some(fileId => !sourceIds.has(fileId))) errors.push(`source set references source outside frozen index: ${sourceSet.source_set_id}`);
    sourceSets.set(sourceSet.source_set_id, sourceSet);
  }
  const sourceSetIds = [...sourceSets.keys()];
  if (JSON.stringify(sourceSetIds) !== JSON.stringify([...sourceSetIds].sort())) errors.push("plan source_sets must be sorted by source set ID");
  const interfaceIndexRows = plan?.interface_index ?? [];
  const interfaceIndex = new Map();
  for (const item of interfaceIndexRows) {
    if (typeof item?.interface_id !== "string" || interfaceIndex.has(item.interface_id)
      || typeof item.file_id !== "string" || !sourceIds.has(item.file_id)
      || !["ingress", "egress", "bidirectional"].includes(item.direction)
      || typeof item.kind !== "string" || item.kind.trim() === ""
      || !Array.isArray(item.dimensions) || item.dimensions.length === 0
      || item.dimensions.some(dimension => !DIMENSIONS.includes(dimension))) {
      errors.push(`invalid frozen interface index row: ${item?.interface_id ?? "<missing>"}`);
      continue;
    }
    interfaceIndex.set(item.interface_id, item);
  }
  const interfaceIndexIds = [...interfaceIndex.keys()];
  if (JSON.stringify(interfaceIndexIds) !== JSON.stringify([...interfaceIndexIds].sort())) {
    errors.push("plan interface_index must be sorted by interface ID");
  }
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
    if (check.applicability === "REQUIRED") {
      const sourceSet = sourceSets.get(check.required_source_set_id);
      if (!sourceSet || !Number.isInteger(check.required_source_count) || check.required_source_count < 1
        || check.required_source_count !== sourceSet.file_ids.length) {
        errors.push(`required source universe missing or duplicated: ${check.check_id}`);
      }
    }
    if (check.required_catalog_ids !== undefined) {
      if (!Array.isArray(check.required_catalog_ids) || check.required_catalog_ids.length === 0
        || new Set(check.required_catalog_ids).size !== check.required_catalog_ids.length
        || JSON.stringify(check.required_catalog_ids) !== JSON.stringify([...check.required_catalog_ids].sort())
        || !check.required_catalog_ids.includes(check.vulnerability_type_id)) {
        errors.push(`invalid required catalog set: ${check.check_id}`);
      }
    }
    if (check.subject_kind === "interface" && check.applicability === "REQUIRED") {
      const requiredInterfaceIds = check.required_interface_ids;
      if (requiredInterfaceIds === undefined && interfaceIndexRows.length === 0) {
        // Compatibility for already-frozen v3 plans that used one check per interface.
      } else if (!Array.isArray(requiredInterfaceIds) || requiredInterfaceIds.length === 0
        || new Set(requiredInterfaceIds).size !== requiredInterfaceIds.length
        || JSON.stringify(requiredInterfaceIds) !== JSON.stringify([...requiredInterfaceIds].sort())
        || requiredInterfaceIds.some(interfaceId => !interfaceIndex.has(interfaceId))) {
        errors.push(`invalid required interface set: ${check.check_id}`);
      } else {
        const expectedSubjectId = interfaceGroupId(
          check.focus_area_id,
          check.domain,
          check.vulnerability_type_id,
          requiredInterfaceIds,
        );
        if (check.subject_id !== expectedSubjectId) errors.push(`invalid interface group id: ${check.check_id}`);
        const expectedSourceIds = [...new Set(requiredInterfaceIds.map(interfaceId => interfaceIndex.get(interfaceId).file_id))].sort();
        const sourceSet = sourceSets.get(check.required_source_set_id);
        if (!sourceSet || JSON.stringify(sourceSet.file_ids) !== JSON.stringify(expectedSourceIds)) {
          errors.push(`interface group source set mismatch: ${check.check_id}`);
        }
      }
    }
    if (check.required_source_file_ids !== undefined) errors.push(`v2 expanded source set is not allowed: ${check.check_id}`);
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
  const catalogRequired = (plan?.checks ?? []).filter(check => check.subject_kind === "catalog-domain" && check.applicability === "REQUIRED").length;
  const interfaceRequired = (plan?.checks ?? []).filter(check => check.subject_kind === "interface" && check.applicability === "REQUIRED").length;
  if (plan?.summary?.catalog_domain_required !== catalogRequired) errors.push("plan catalog-domain required count mismatch");
  if (plan?.summary?.interface_required !== interfaceRequired) errors.push("plan interface required count mismatch");
  const inventory = plan?.inventory;
  for (const field of [
    "eligible_files",
    "resolved_files",
    "gap_files",
    "confirmed_interfaces",
    "candidate_interfaces",
    "rejected_interfaces",
    "unresolved_interfaces",
  ]) {
    if (!Number.isInteger(inventory?.[field]) || inventory[field] < 0) errors.push(`interface inventory ${field} must be a non-negative integer`);
  }
  const gapFileIds = inventory?.gap_file_ids ?? [];
  const candidateInterfaceIds = inventory?.candidate_interface_ids ?? [];
  if (!Array.isArray(gapFileIds) || new Set(gapFileIds).size !== gapFileIds.length
    || JSON.stringify(gapFileIds) !== JSON.stringify([...gapFileIds].sort())
    || gapFileIds.some(fileId => !sourceIds.has(fileId))) {
    errors.push("interface inventory gap file IDs are invalid");
  }
  if (!Array.isArray(candidateInterfaceIds) || new Set(candidateInterfaceIds).size !== candidateInterfaceIds.length
    || JSON.stringify(candidateInterfaceIds) !== JSON.stringify([...candidateInterfaceIds].sort())) {
    errors.push("interface inventory candidate IDs are invalid");
  }
  if (inventory?.gap_files !== gapFileIds.length) errors.push("interface inventory gap file count mismatch");
  if (inventory?.candidate_interfaces !== candidateInterfaceIds.length) errors.push("interface inventory candidate count mismatch");
  if (inventory?.confirmed_interfaces !== plan?.universes?.interfaces) errors.push("confirmed interface universe mismatch");
  if (interfaceIndexRows.length > 0 && interfaceIndex.size !== inventory?.confirmed_interfaces) {
    errors.push("frozen interface index count mismatch");
  }
  if ((inventory?.confirmed_interfaces ?? -1) + (inventory?.candidate_interfaces ?? -1)
    + (inventory?.rejected_interfaces ?? -1) + (inventory?.unresolved_interfaces ?? -1)
    !== plan?.universes?.interface_anchors) {
    errors.push("interface anchor inventory count mismatch");
  }
  const expectedBounded = inventory?.gap_files === 0 && inventory?.candidate_interfaces === 0
    && inventory?.unresolved_interfaces === 0 && inventory?.extractor_complete === true;
  if (inventory?.bounded !== expectedBounded) errors.push("interface inventory bounded state mismatch");
  if (inventory?.eligible_files !== (plan?.universes?.files ?? -1)) errors.push("interface inventory eligible file count mismatch");
  if ((inventory?.resolved_files ?? -1) + (inventory?.gap_files ?? -1) !== inventory?.eligible_files) errors.push("interface inventory file accounting mismatch");
  if (plan?.complete !== (counts.UNKNOWN === 0 && expectedBounded)) errors.push("plan completeness mismatch");
  if (plan?.summary?.interface_memberships_required !== undefined) {
    const interfaceMemberships = (plan?.checks ?? [])
      .filter(check => check.subject_kind === "interface" && check.applicability === "REQUIRED")
      .reduce((sum, check) => sum + (check.required_interface_ids?.length ?? 0), 0);
    if (plan.summary.interface_memberships_required !== interfaceMemberships) {
      errors.push("plan interface membership count mismatch");
    }
  }
  if (plan?.execution_model !== undefined) {
    if (plan.execution_model !== COVERAGE_EXECUTION_MODEL) errors.push("invalid coverage execution model");
    if (!COVERAGE_POLICY_MODES.includes(plan?.coverage_policy?.mode)) errors.push("invalid coverage policy mode");
    if (plan?.coverage_policy?.assurance_requires_all_checks !== true) errors.push("coverage assurance policy must require all checks");
    const requiredChecks = new Map((plan?.checks ?? [])
      .filter(check => check.applicability === "REQUIRED")
      .map(check => [check.check_id, check]));
    const observedCheckIds = new Set();
    const unitIds = new Set();
    const units = plan?.coverage_units ?? [];
    for (const unit of units) {
      const checkIds = unit?.check_ids;
      if (typeof unit?.unit_id !== "string" || unitIds.has(unit.unit_id)
        || typeof unit.assignment_id !== "string" || typeof unit.focus_area_id !== "string"
        || !Object.hasOwn(DOMAIN_AGENTS, unit.domain) || unit.agent_name !== DOMAIN_AGENTS[unit.domain]
        || !exactArray(unit.required_lenses, LENSES)
        || !Array.isArray(checkIds) || checkIds.length === 0
        || new Set(checkIds).size !== checkIds.length
        || JSON.stringify(checkIds) !== JSON.stringify([...checkIds].sort())) {
        errors.push(`invalid coverage unit: ${unit?.unit_id ?? "<missing>"}`);
        continue;
      }
      unitIds.add(unit.unit_id);
      if (!Array.isArray(unit.policy_tags) || new Set(unit.policy_tags).size !== unit.policy_tags.length
        || JSON.stringify(unit.policy_tags) !== JSON.stringify([...unit.policy_tags].sort())
        || unit.policy_tags.some(tag => !["ai-boundary", "external-interface", "identity-or-privilege"].includes(tag))) {
        errors.push(`coverage unit policy tags are invalid: ${unit.unit_id}`);
      }
      const expectedUnitId = coverageUnitId(unit.assignment_id, unit.focus_area_id, unit.domain, checkIds);
      if (unit.unit_id !== expectedUnitId) errors.push(`invalid coverage unit id: ${unit.unit_id}`);
      if (unit.check_set_sha256 !== sha256(JSON.stringify(checkIds))) errors.push(`invalid coverage unit check digest: ${unit.unit_id}`);
      if (unit.required_check_count !== checkIds.length) errors.push(`coverage unit check count mismatch: ${unit.unit_id}`);
      const unitChecks = checkIds.map(checkId => requiredChecks.get(checkId));
      if (unitChecks.some(check => !check)) errors.push(`coverage unit references unknown required check: ${unit.unit_id}`);
      if (unitChecks.some(check => check && (check.focus_area_id !== unit.focus_area_id || check.domain !== unit.domain))) {
        errors.push(`coverage unit check scope mismatch: ${unit.unit_id}`);
      }
      for (const checkId of checkIds) {
        if (observedCheckIds.has(checkId)) errors.push(`coverage check belongs to multiple units: ${checkId}`);
        observedCheckIds.add(checkId);
      }
      const expectedSourceIds = [...new Set(unitChecks.filter(Boolean)
        .flatMap(check => sourceFileIdsForCheck(plan, check)))].sort();
      const unitSourceSet = sourceSets.get(unit.required_source_set_id);
      if (!unitSourceSet || unit.required_source_count !== expectedSourceIds.length
        || JSON.stringify(unitSourceSet.file_ids) !== JSON.stringify(expectedSourceIds)) {
        errors.push(`coverage unit source set mismatch: ${unit.unit_id}`);
      }
      const expectedCatalogCount = new Set(unitChecks.filter(Boolean).map(check => check.vulnerability_type_id)).size;
      const expectedInterfaceCount = new Set(unitChecks.filter(Boolean)
        .flatMap(check => check.required_interface_ids ?? (check.subject_kind === "interface" ? [check.subject_id] : []))).size;
      if (unit.required_catalog_count !== expectedCatalogCount || unit.required_interface_count !== expectedInterfaceCount) {
        errors.push(`coverage unit member count mismatch: ${unit.unit_id}`);
      }
    }
    if (units.length === 0) errors.push("coverage units must be non-empty");
    if (JSON.stringify(units.map(unit => unit.unit_id)) !== JSON.stringify(units.map(unit => unit.unit_id).sort())) {
      errors.push("coverage units must be sorted by unit ID");
    }
    for (const checkId of requiredChecks.keys()) {
      if (!observedCheckIds.has(checkId)) errors.push(`required check is not assigned to a coverage unit: ${checkId}`);
    }
    if (plan?.summary?.coverage_units !== units.length) errors.push("plan coverage unit count mismatch");
    const releaseUnits = plan?.coverage_policy?.release_required_unit_ids ?? [];
    if (!Array.isArray(releaseUnits) || new Set(releaseUnits).size !== releaseUnits.length
      || JSON.stringify(releaseUnits) !== JSON.stringify([...releaseUnits].sort())
      || releaseUnits.some(unitId => !unitIds.has(unitId))) {
      errors.push("coverage policy release unit set is invalid");
    }
    const expectedReleaseUnits = units.filter(unit => unit.policy_tags?.length > 0).map(unit => unit.unit_id).sort();
    if (JSON.stringify(releaseUnits) !== JSON.stringify(expectedReleaseUnits)) {
      errors.push("coverage policy release unit set does not match policy-tagged units");
    }
  }
  if (plan?.manifest_digest !== objectDigest(plan)) errors.push("plan manifest digest mismatch");
  return [...new Set(errors)];
}
