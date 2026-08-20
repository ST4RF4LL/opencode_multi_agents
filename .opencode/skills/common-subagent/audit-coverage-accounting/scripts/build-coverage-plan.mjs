#!/usr/bin/env node

import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import {
  COVERAGE_EXECUTION_MODEL,
  COVERAGE_MODEL_VERSION,
  COVERAGE_POLICY_MODES,
  LENSES,
  DOMAIN_AGENTS,
  PLAN_SCHEMA_VERSION,
  activeDomains,
  coverageCheckId,
  coverageUnitId,
  entryAppliesToDomain,
  functionManifestMembership,
  interfaceApplicability,
  interfaceDomains,
  interfaceGroupId,
  objectDigest,
  sha256,
  sourceSetId,
  validateCatalogV2,
  validateFocusAreaPartition,
} from "./coverage-v2-common.mjs";

function parseArgs(argv) {
  const args = { functions: [], "coverage-mode": "observe" };
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    const key = token.slice(2);
    if (key === "functions") args.functions.push(value);
    else args[key] = value;
  }
  for (const key of ["audit-id", "catalog", "output"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  }
  const directRecon = typeof args["recon-dir"] === "string" && args["recon-dir"];
  if (!directRecon) {
    for (const key of ["scope", "interfaces", "interface-extractors", "focus-areas", "snapshot-index"]) {
      if (!args[key]) throw new Error(`Required argument missing: --${key}`);
    }
    if (args.functions.length === 0) throw new Error("At least one --functions manifest is required");
  } else if (["scope", "interfaces", "interface-extractors", "focus-areas", "snapshot-index"].some(key => args[key]) || args.functions.length > 0) {
    throw new Error("--recon-dir 不能与 --scope、--functions、--interfaces、--interface-extractors、--focus-areas 或 --snapshot-index 混用。");
  }
  if (!COVERAGE_POLICY_MODES.includes(args["coverage-mode"])) {
    throw new Error(`--coverage-mode must be one of: ${COVERAGE_POLICY_MODES.join(", ")}`);
  }
  return args;
}

// New local-todo audits use one short command.  The recon directory is already
// the frozen source of truth, so copying every manifest into reports/coverage
// and spelling every language path on the command line adds no scheduling value.
async function resolveReconInputs(args) {
  if (!args["recon-dir"]) return args;
  const recon = resolve(args["recon-dir"]);
  const coverage = join(recon, "coverage");
  let entries;
  try {
    entries = await readdir(coverage, { withFileTypes: true });
  } catch (error) {
    throw new Error(`无法读取 Recon 覆盖清单目录：${coverage}（${error.code ?? error.message}）`);
  }
  const functions = entries
    .filter(entry => entry.isFile() && /^functions-.+\.json$/u.test(entry.name))
    .map(entry => join(coverage, entry.name))
    .sort();
  if (functions.length === 0) throw new Error("Recon 目录中没有 functions-<language>.json 清单。");
  return {
    ...args,
    scope: join(coverage, "scope-manifest.json"),
    interfaces: join(coverage, "interface-manifest.json"),
    "interface-extractors": join(coverage, "interface-extractor-coverage.json"),
    "focus-areas": join(recon, "focus-areas.json"),
    functions,
  };
}

function summarizedErrors(prefix, errors, limit = 20) {
  const values = [...new Set(errors.map(value => String(value)))];
  const visible = values.slice(0, limit);
  const omitted = values.length - visible.length;
  return `${prefix}:\n- ${visible.join("\n- ")}${omitted > 0 ? `\n- …另有 ${omitted} 项，已省略以避免占满上下文。` : ""}`;
}

function requiredCheck(subjectKind, subjectId, entry, domain, lens, catalog, focusAreaId, extra = {}) {
  const contract = catalog.coverage_model.evidence_contracts[lens];
  return {
    check_id: coverageCheckId(subjectKind, subjectId, entry.id, domain, lens),
    subject_kind: subjectKind,
    subject_id: subjectId,
    vulnerability_type_id: entry.id,
    domain,
    lens,
    focus_area_id: focusAreaId,
    dimensions: entry.dimensions,
    applicability: "REQUIRED",
    applicability_reason: subjectKind === "catalog-domain"
      ? "active-domain-vulnerability-type-negative-discovery-baseline"
      : "domain-applicable-and-dimension-intersection",
    negative_discovery_required: subjectKind === "catalog-domain",
    evidence_contract: {
      required_receipt_fields: contract.required_receipt_fields,
      question_field: contract.decision_question_field,
      question: entry[contract.decision_question_field],
    },
    ...extra,
  };
}

async function readManifest(path) {
  return JSON.parse(await readFile(resolve(path), "utf8"));
}

async function assertSnapshotFile(path, entry, label) {
  const absolute = resolve(path);
  if (!entry || resolve(entry.path) !== absolute) throw new Error(`Snapshot index ${label} path mismatch: ${absolute}`);
  const bytes = await readFile(absolute);
  if (entry.sha256 !== sha256(bytes)) throw new Error(`Snapshot index ${label} byte digest mismatch: ${absolute}`);
}

async function main() {
  const args = await resolveReconInputs(parseArgs(process.argv.slice(2)));
  const [scope, interfaces, extractorCoverage, catalog, focusAreas] = await Promise.all([
    readManifest(args.scope),
    readManifest(args.interfaces),
    readManifest(args["interface-extractors"]),
    readManifest(args.catalog),
    readManifest(args["focus-areas"]),
  ]);
  const snapshot = args["snapshot-index"] ? await readManifest(args["snapshot-index"]) : null;
  const catalogErrors = validateCatalogV2(catalog);
  if (catalogErrors.length > 0) throw new Error(summarizedErrors("Catalog v2 is invalid", catalogErrors));
  if (scope.audit_id !== args["audit-id"] || scope.manifest_digest !== objectDigest(scope) || !scope.complete) {
    throw new Error("Scope manifest is incomplete, modified, or bound to another audit");
  }
  if (interfaces.audit_id !== args["audit-id"] || interfaces.scope_digest !== scope.scope_digest
    || interfaces.manifest_digest !== objectDigest(interfaces)) {
    throw new Error("Interface manifest is modified or scope-mismatched");
  }
  if (extractorCoverage.audit_id !== args["audit-id"] || extractorCoverage.scope_digest !== scope.scope_digest
    || extractorCoverage.interface_manifest_digest !== interfaces.manifest_digest
    || extractorCoverage.manifest_digest !== objectDigest(extractorCoverage)) {
    throw new Error("Interface extractor verification is modified or scope-mismatched");
  }
  if (focusAreas.audit_id !== args["audit-id"] || focusAreas.scope_digest !== scope.scope_digest
    || focusAreas.manifest_digest !== objectDigest(focusAreas)) {
    throw new Error("Focus Area manifest is modified or scope-mismatched");
  }
  if (snapshot) {
    if (snapshot.schema_version !== 2 || snapshot.audit_id !== args["audit-id"] || snapshot.scope_digest !== scope.scope_digest
      || snapshot.snapshot_digest !== objectDigest(snapshot, ["snapshot_digest"])) {
      throw new Error("Snapshot index is modified or scope-mismatched");
    }
    await Promise.all([
      assertSnapshotFile(args.scope, snapshot.scope, "scope"),
      assertSnapshotFile(args.interfaces, snapshot.interfaces, "interfaces"),
      assertSnapshotFile(args["interface-extractors"], snapshot.interface_extractors, "interface extractors"),
      assertSnapshotFile(args.catalog, snapshot.catalog, "catalog"),
      assertSnapshotFile(args["focus-areas"], snapshot.semantic?.focus_areas, "Focus Areas"),
    ]);
  }

  const functionInputs = [];
  const functionManifests = [];
  const expectedFiles = new Set();
  const functionIds = new Set();
  for (const path of args.functions) {
    const manifest = await readManifest(path);
    if (manifest.audit_id !== args["audit-id"] || manifest.scope_digest !== scope.scope_digest
      || !manifest.complete || manifest.manifest_digest !== objectDigest(manifest)) {
      throw new Error(`Function manifest is incomplete, modified, or scope-mismatched: ${path}`);
    }
    if (snapshot) {
      const snapshotEntry = snapshot.functions?.find(item => item.language === manifest.language);
      await assertSnapshotFile(path, snapshotEntry, `function manifest ${manifest.language}`);
    }
    functionInputs.push({ language: manifest.language, manifest_digest: manifest.manifest_digest, functions: manifest.functions.length });
    functionManifests.push(manifest);
    for (const fileId of manifest.expected_files ?? []) expectedFiles.add(fileId);
    for (const fn of manifest.functions ?? []) functionIds.add(fn.function_id);
  }
  if (snapshot && functionManifests.length !== (snapshot.functions?.length ?? 0)) {
    throw new Error("Coverage Plan function manifest set does not exactly match the snapshot index");
  }
  const membership = functionManifestMembership(scope, functionManifests);
  if (membership.missing.length > 0 || membership.duplicates.length > 0) {
    const issues = [
      ...membership.missing.map(file => `缺失函数清单：${file.path}`),
      ...membership.duplicates.map(value => `重复函数清单：${value}`),
    ];
    throw new Error(summarizedErrors("Coverage Plan requires complete function inventory", issues));
  }

  const focusErrors = validateFocusAreaPartition({ scope, functionManifests, catalog, focusAreas });
  if (focusErrors.length > 0) throw new Error(summarizedErrors("Focus Area primary assignments are invalid", focusErrors));

  const domains = activeDomains(scope);
  const domainSourceIds = new Map(domains.map(domain => [
    domain,
    (scope.files ?? []).filter(file => file.review_required
      && (domain === "ai" || file.owner_agent === DOMAIN_AGENTS[domain])).map(file => file.file_id).sort(),
  ]));
  const applicableEntriesByDomain = new Map(domains.map(domain => [
    domain,
    catalog.entries.filter(entry => entryAppliesToDomain(entry, domain, catalog)),
  ]));
  const catalogFocus = new Map();
  const fileFocus = new Map();
  const unitAssignments = [];
  function bindUnique(map, key, focusAreaId, kind) {
    const prior = map.get(key);
    if (prior && prior !== focusAreaId) throw new Error(`${kind} is assigned to multiple Focus Areas: ${key}`);
    map.set(key, focusAreaId);
  }
  for (const focusArea of focusAreas.focus_areas ?? []) {
    for (const assignment of focusArea.assignments ?? []) {
      const domain = assignment.catalog_domain;
      if (domains.includes(domain)) unitAssignments.push({ focus_area_id: focusArea.focus_area_id, domain, assignment });
      for (const catalogId of assignment.catalog_ids ?? []) bindUnique(catalogFocus, `${domain}|${catalogId}`, focusArea.focus_area_id, "Catalog type");
      const coverageDomain = assignment.file_function_domain === "ai" ? "ai" : assignment.language;
      for (const fileId of assignment.file_ids ?? []) bindUnique(fileFocus, `${coverageDomain}|${fileId}`, focusArea.focus_area_id, "Interface source file");
    }
  }
  const checks = [];
  const checksByFocusDomain = new Map();
  const addCheck = check => {
    checks.push(check);
    const key = `${check.focus_area_id}\u0000${check.domain}`;
    const values = checksByFocusDomain.get(key) ?? [];
    values.push(check);
    checksByFocusDomain.set(key, values);
  };
  const sourceSets = new Map();
  const sourceSetIdsByMembers = new Map();
  const bindSourceSet = fileIds => {
    const canonical = [...fileIds].sort();
    const memberKey = canonical.join("\u0000");
    const existing = sourceSetIdsByMembers.get(memberKey);
    if (existing) return existing;
    const id = sourceSetId(canonical);
    sourceSets.set(id, { source_set_id: id, file_ids: canonical });
    sourceSetIdsByMembers.set(memberKey, id);
    return id;
  };
  const domainSourceSetIds = new Map(domains.map(domain => [
    domain,
    bindSourceSet(domainSourceIds.get(domain)),
  ]));
  for (const domain of domains) {
    for (const entry of applicableEntriesByDomain.get(domain)) {
      const focusAreaId = catalogFocus.get(`${domain}|${entry.id}`);
      if (!focusAreaId) throw new Error(`Catalog type lacks a unique primary Focus Area assignment: ${domain}|${entry.id}`);
      for (const lens of LENSES) addCheck(requiredCheck("catalog-domain", `domain:${domain}`, entry, domain, lens, catalog, focusAreaId, {
        required_source_set_id: domainSourceSetIds.get(domain),
        required_source_count: domainSourceIds.get(domain).length,
        required_catalog_ids: [entry.id],
        required_interface_ids: [],
      }));
    }
  }

  const confirmedInterfaces = (interfaces.interfaces ?? []).filter(item => item.discovery_state === "CONFIRMED");
  const candidateInterfaces = (interfaces.interfaces ?? []).filter(item => item.discovery_state === "CANDIDATE");
  const rejectedInterfaces = (interfaces.interfaces ?? []).filter(item => item.discovery_state === "REJECTED");
  const unresolvedInterfaces = (interfaces.interfaces ?? []).filter(item => !["CONFIRMED", "CANDIDATE", "REJECTED"].includes(item.discovery_state));
  const coverageRows = new Map((interfaces.file_coverage ?? []).map(row => [row.file_id, row]));
  const eligibleFiles = (scope.files ?? []).filter(file => file.review_required);
  const gapFiles = eligibleFiles.filter(file => {
    const state = coverageRows.get(file.file_id)?.state;
    return !["INSPECTED", "NOT_APPLICABLE"].includes(state);
  });
  const resolvedFiles = eligibleFiles.length - gapFiles.length;
  const extractorComplete = interfaces.complete === true && extractorCoverage.complete === true;
  const inventoryBounded = extractorComplete && gapFiles.length === 0
    && candidateInterfaces.length === 0 && unresolvedInterfaces.length === 0;

  const interfaceGroups = new Map();
  for (const item of confirmedInterfaces) {
    const itemDimensions = new Set(item.dimensions ?? []);
    for (const domain of interfaceDomains(item).filter(candidate => domains.includes(candidate))) {
      const focusAreaId = fileFocus.get(`${domain}|${item.file_id}`);
      if (!focusAreaId) throw new Error(`Interface source lacks a unique primary Focus Area assignment: ${domain}|${item.file_id}`);
      for (const entry of applicableEntriesByDomain.get(domain)) {
        const applicability = interfaceApplicability(entry, domain, item, catalog);
        const intersects = entry.dimensions.some(dimension => itemDimensions.has(dimension));
        for (const lens of LENSES) {
          if (applicability.applicability !== "REQUIRED" || !intersects) continue;
          const groupKey = [focusAreaId, domain, entry.id, lens].join("|");
          const group = interfaceGroups.get(groupKey) ?? {
            focus_area_id: focusAreaId,
            domain,
            entry,
            lens,
            interfaces: new Map(),
            rule_ids: new Set(),
          };
          group.interfaces.set(item.interface_id, item);
          if (applicability.rule_id) group.rule_ids.add(applicability.rule_id);
          interfaceGroups.set(groupKey, group);
        }
      }
    }
  }

  for (const group of interfaceGroups.values()) {
    const items = [...group.interfaces.values()].sort((left, right) => left.interface_id.localeCompare(right.interface_id));
    const interfaceIds = items.map(item => item.interface_id);
    const sourceFileIds = [...new Set(items.map(item => item.file_id))].sort();
    const subjectId = interfaceGroupId(group.focus_area_id, group.domain, group.entry.id, interfaceIds);
    addCheck(requiredCheck("interface", subjectId, group.entry, group.domain, group.lens, catalog, group.focus_area_id, {
      applicability_reason: "explicit-interface-rule-and-dimension-intersection",
      applicability_rule_ids: [...group.rule_ids].sort(),
      interface_directions: [...new Set(items.map(item => item.direction))].sort(),
      interface_kinds: [...new Set(items.map(item => item.kind))].sort(),
      required_source_set_id: bindSourceSet(sourceFileIds),
      required_source_count: sourceFileIds.length,
      required_catalog_ids: [group.entry.id],
      required_interface_ids: interfaceIds,
    }));
  }

  checks.sort((left, right) => left.check_id.localeCompare(right.check_id));
  const coverageUnits = [];
  for (const { focus_area_id: focusAreaId, domain, assignment } of unitAssignments) {
      const unitChecks = checksByFocusDomain.get(`${focusAreaId}\u0000${domain}`) ?? [];
      if (unitChecks.length === 0) continue;
      const checkIds = unitChecks.map(check => check.check_id).sort();
      const baselineCheck = unitChecks.find(check => check.subject_kind === "catalog-domain");
      const baselineSourceSet = baselineCheck ? sourceSets.get(baselineCheck.required_source_set_id) : null;
      if (baselineCheck && !baselineSourceSet) throw new Error(`Coverage unit check references an unknown source set: ${baselineCheck.check_id}`);
      const sourceFileIds = baselineSourceSet
        ? baselineSourceSet.file_ids
        : [...new Set(unitChecks.flatMap(check => {
          const sourceSet = sourceSets.get(check.required_source_set_id);
          if (!sourceSet) throw new Error(`Coverage unit check references an unknown source set: ${check.check_id}`);
          return sourceSet.file_ids;
        }))].sort();
      const unitSourceSetId = baselineSourceSet?.source_set_id ?? bindSourceSet(sourceFileIds);
      const catalogIds = new Set(unitChecks.map(check => check.vulnerability_type_id));
      const interfaceIds = new Set(unitChecks.flatMap(check => check.required_interface_ids ?? []));
      const policyTags = new Set();
      if (domain === "ai") policyTags.add("ai-boundary");
      if (unitChecks.some(check => check.subject_kind === "interface"
        && (check.interface_directions ?? [check.interface_direction]).some(direction => ["ingress", "bidirectional"].includes(direction)))) {
        policyTags.add("external-interface");
      }
      if (unitChecks.some(check => /^(?:JW-(?:ACCESS|AUTHN)-|AI-(?:ACCESS|IDENTITY|TOOL)-)/.test(check.vulnerability_type_id))) {
        policyTags.add("identity-or-privilege");
      }
      const unitId = coverageUnitId(assignment.assignment_id, focusAreaId, domain, checkIds);
      coverageUnits.push({
        unit_id: unitId,
        assignment_id: assignment.assignment_id,
        focus_area_id: focusAreaId,
        domain,
        agent_name: assignment.agent_name,
        required_lenses: LENSES,
        check_ids: checkIds,
        check_set_sha256: sha256(JSON.stringify(checkIds)),
        required_check_count: checkIds.length,
        required_source_set_id: unitSourceSetId,
        required_source_count: sourceFileIds.length,
        required_catalog_count: catalogIds.size,
        required_interface_count: interfaceIds.size,
        policy_tags: [...policyTags].sort(),
      });
  }
  coverageUnits.sort((left, right) => left.unit_id.localeCompare(right.unit_id));
  const releaseRequiredUnitIds = coverageUnits
    .filter(unit => unit.policy_tags.length > 0)
    .map(unit => unit.unit_id)
    .sort();
  const counts = Object.fromEntries(["REQUIRED", "NOT_APPLICABLE", "UNKNOWN"].map(state => [
    state,
    checks.filter(check => check.applicability === state).length,
  ]));
  const plan = {
    schema_version: PLAN_SCHEMA_VERSION,
    coverage_model_version: COVERAGE_MODEL_VERSION,
    execution_model: COVERAGE_EXECUTION_MODEL,
    coverage_policy: {
      mode: args["coverage-mode"],
      release_required_unit_ids: releaseRequiredUnitIds,
      assurance_requires_all_checks: true,
    },
    audit_id: args["audit-id"],
    catalog_profile_id: catalog.profile_id,
    scope_digest: scope.scope_digest,
    required_lenses: LENSES,
    inputs: {
      ...(snapshot ? { snapshot_digest: snapshot.snapshot_digest, input_mode: "legacy-snapshot" } : { input_mode: "direct-recon" }),
      scope_manifest_digest: scope.manifest_digest,
      interface_manifest_digest: interfaces.manifest_digest,
      interface_extractor_manifest_digest: extractorCoverage.manifest_digest,
      catalog_digest: objectDigest(catalog, []),
      focus_areas_digest: focusAreas.manifest_digest,
      function_manifests: functionInputs.sort((a, b) => a.language.localeCompare(b.language)),
    },
    source_index: (scope.files ?? []).filter(file => file.review_required).map(file => ({
      file_id: file.file_id,
      path: file.path,
      type: file.type,
      sha256: file.sha256 ?? null,
      link_target: file.link_target ?? null,
      owner_agent: file.owner_agent,
    })).sort((a, b) => a.file_id.localeCompare(b.file_id)),
    source_sets: [...sourceSets.values()].sort((a, b) => a.source_set_id.localeCompare(b.source_set_id)),
    interface_index: confirmedInterfaces.map(item => ({
      interface_id: item.interface_id,
      file_id: item.file_id,
      direction: item.direction,
      kind: item.kind,
      protocol: item.protocol,
      operation: item.operation,
      address: item.address,
      line_start: item.line_start,
      dimensions: [...item.dimensions].sort(),
    })).sort((left, right) => left.interface_id.localeCompare(right.interface_id)),
    universes: {
      files: (scope.files ?? []).filter(file => file.review_required).length,
      function_files: expectedFiles.size,
      functions: functionIds.size,
      interfaces: confirmedInterfaces.length,
      interface_anchors: interfaces.interfaces?.length ?? 0,
      vulnerability_types: catalog.entries.length,
      active_domains: domains,
    },
    inventory: {
      eligible_files: eligibleFiles.length,
      resolved_files: resolvedFiles,
      gap_files: gapFiles.length,
      gap_file_ids: gapFiles.map(file => file.file_id).sort(),
      confirmed_interfaces: confirmedInterfaces.length,
      candidate_interfaces: candidateInterfaces.length,
      candidate_interface_ids: candidateInterfaces.map(item => item.interface_id).sort(),
      rejected_interfaces: rejectedInterfaces.length,
      unresolved_interfaces: unresolvedInterfaces.length,
      extractor_complete: extractorComplete,
      bounded: inventoryBounded,
    },
    checks,
    coverage_units: coverageUnits,
    summary: {
      atomic_checks: checks.length,
      required: counts.REQUIRED,
      not_applicable: counts.NOT_APPLICABLE,
      unknown: counts.UNKNOWN,
      catalog_domain_required: checks.filter(check => check.subject_kind === "catalog-domain" && check.applicability === "REQUIRED").length,
      interface_required: checks.filter(check => check.subject_kind === "interface" && check.applicability === "REQUIRED").length,
      interface_memberships_required: checks
        .filter(check => check.subject_kind === "interface" && check.applicability === "REQUIRED")
        .reduce((sum, check) => sum + check.required_interface_ids.length, 0),
      coverage_units: coverageUnits.length,
    },
    complete: counts.UNKNOWN === 0 && inventoryBounded,
    claim_boundary: catalog.coverage_model.claim_boundary,
  };
  plan.manifest_digest = objectDigest(plan);
  const output = resolve(args.output);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(plan, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output, manifest_digest: plan.manifest_digest, complete: plan.complete, ...plan.summary, universes: plan.universes })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
