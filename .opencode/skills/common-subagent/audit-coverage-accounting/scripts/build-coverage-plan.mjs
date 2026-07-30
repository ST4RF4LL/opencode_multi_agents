#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import {
  COVERAGE_MODEL_VERSION,
  LENSES,
  DOMAIN_AGENTS,
  PLAN_SCHEMA_VERSION,
  activeDomains,
  coverageCheckId,
  entryAppliesToDomain,
  functionManifestMembership,
  interfaceApplicability,
  interfaceDomains,
  objectDigest,
  sha256,
  sourceSetId,
  validateCatalogV2,
  validateFocusAreaPartition,
  validatePlan,
} from "./coverage-v2-common.mjs";

function parseArgs(argv) {
  const args = { functions: [] };
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    const key = token.slice(2);
    if (key === "functions") args.functions.push(value);
    else args[key] = value;
  }
  for (const key of ["audit-id", "scope", "interfaces", "interface-extractors", "catalog", "focus-areas", "snapshot-index", "output"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  }
  if (args.functions.length === 0) throw new Error("At least one --functions manifest is required");
  return args;
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
  const args = parseArgs(process.argv.slice(2));
  const [scope, interfaces, extractorCoverage, catalog, focusAreas, snapshot] = await Promise.all([
    readManifest(args.scope),
    readManifest(args.interfaces),
    readManifest(args["interface-extractors"]),
    readManifest(args.catalog),
    readManifest(args["focus-areas"]),
    readManifest(args["snapshot-index"]),
  ]);
  const catalogErrors = validateCatalogV2(catalog);
  if (catalogErrors.length > 0) throw new Error(`Catalog v2 is invalid:\n- ${catalogErrors.join("\n- ")}`);
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
    const snapshotEntry = snapshot.functions?.find(item => item.language === manifest.language);
    await assertSnapshotFile(path, snapshotEntry, `function manifest ${manifest.language}`);
    functionInputs.push({ language: manifest.language, manifest_digest: manifest.manifest_digest, functions: manifest.functions.length });
    functionManifests.push(manifest);
    for (const fileId of manifest.expected_files ?? []) expectedFiles.add(fileId);
    for (const fn of manifest.functions ?? []) functionIds.add(fn.function_id);
  }
  if (functionManifests.length !== (snapshot.functions?.length ?? 0)) {
    throw new Error("Coverage Plan function manifest set does not exactly match the snapshot index");
  }
  const membership = functionManifestMembership(scope, functionManifests);
  if (membership.missing.length > 0 || membership.duplicates.length > 0) {
    throw new Error(`Coverage Plan requires complete function inventory: missing=${membership.missing.map(file => file.path).join(",") || "none"}; duplicate=${membership.duplicates.join(",") || "none"}`);
  }

  const focusErrors = validateFocusAreaPartition({ scope, functionManifests, catalog, focusAreas });
  if (focusErrors.length > 0) throw new Error(`Focus Area primary assignments are invalid:\n- ${focusErrors.join("\n- ")}`);

  const domains = activeDomains(scope);
  const domainSourceIds = new Map(domains.map(domain => [
    domain,
    (scope.files ?? []).filter(file => file.review_required
      && (domain === "ai" || file.owner_agent === DOMAIN_AGENTS[domain])).map(file => file.file_id).sort(),
  ]));
  const catalogFocus = new Map();
  const fileFocus = new Map();
  function bindUnique(map, key, focusAreaId, kind) {
    const prior = map.get(key);
    if (prior && prior !== focusAreaId) throw new Error(`${kind} is assigned to multiple Focus Areas: ${key}`);
    map.set(key, focusAreaId);
  }
  for (const focusArea of focusAreas.focus_areas ?? []) {
    for (const assignment of focusArea.assignments ?? []) {
      const domain = assignment.catalog_domain;
      for (const catalogId of assignment.catalog_ids ?? []) bindUnique(catalogFocus, `${domain}|${catalogId}`, focusArea.focus_area_id, "Catalog type");
      const coverageDomain = assignment.file_function_domain === "ai" ? "ai" : assignment.language;
      for (const fileId of assignment.file_ids ?? []) bindUnique(fileFocus, `${coverageDomain}|${fileId}`, focusArea.focus_area_id, "Interface source file");
    }
  }
  const checks = [];
  const sourceSets = new Map();
  const bindSourceSet = fileIds => {
    const canonical = [...fileIds].sort();
    const id = sourceSetId(canonical);
    sourceSets.set(id, { source_set_id: id, file_ids: canonical });
    return id;
  };
  for (const domain of domains) {
    for (const entry of catalog.entries.filter(item => entryAppliesToDomain(item, domain, catalog))) {
      const focusAreaId = catalogFocus.get(`${domain}|${entry.id}`);
      if (!focusAreaId) throw new Error(`Catalog type lacks a unique primary Focus Area assignment: ${domain}|${entry.id}`);
      for (const lens of LENSES) checks.push(requiredCheck("catalog-domain", `domain:${domain}`, entry, domain, lens, catalog, focusAreaId, {
        required_source_set_id: bindSourceSet(domainSourceIds.get(domain)),
        required_source_count: domainSourceIds.get(domain).length,
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

  for (const item of confirmedInterfaces) {
    for (const domain of interfaceDomains(item).filter(candidate => domains.includes(candidate))) {
      const focusAreaId = fileFocus.get(`${domain}|${item.file_id}`);
      if (!focusAreaId) throw new Error(`Interface source lacks a unique primary Focus Area assignment: ${domain}|${item.file_id}`);
      for (const entry of catalog.entries.filter(candidate => entryAppliesToDomain(candidate, domain, catalog))) {
        const applicability = interfaceApplicability(entry, domain, item, catalog);
        for (const lens of LENSES) {
          if (applicability.applicability === "REQUIRED") {
            checks.push(requiredCheck("interface", item.interface_id, entry, domain, lens, catalog, focusAreaId, {
              applicability_reason: applicability.reason,
              applicability_rule_id: applicability.rule_id,
              interface_direction: item.direction,
              interface_kind: item.kind,
              source_file_id: item.file_id,
              required_source_set_id: bindSourceSet([item.file_id]),
              required_source_count: 1,
            }));
          } else {
            checks.push({
              check_id: coverageCheckId("interface", item.interface_id, entry.id, domain, lens),
              subject_kind: "interface",
              subject_id: item.interface_id,
              vulnerability_type_id: entry.id,
              domain,
              lens,
              focus_area_id: focusAreaId,
              dimensions: entry.dimensions,
              applicability: applicability.applicability,
              applicability_reason: applicability.reason,
              applicability_rule_id: applicability.rule_id,
              negative_discovery_required: false,
              interface_direction: item.direction,
              interface_kind: item.kind,
              source_file_id: item.file_id,
            });
          }
        }
      }
    }
  }

  checks.sort((left, right) => left.check_id.localeCompare(right.check_id));
  const counts = Object.fromEntries(["REQUIRED", "NOT_APPLICABLE", "UNKNOWN"].map(state => [
    state,
    checks.filter(check => check.applicability === state).length,
  ]));
  const plan = {
    schema_version: PLAN_SCHEMA_VERSION,
    coverage_model_version: COVERAGE_MODEL_VERSION,
    audit_id: args["audit-id"],
    catalog_profile_id: catalog.profile_id,
    scope_digest: scope.scope_digest,
    required_lenses: LENSES,
    inputs: {
      snapshot_digest: snapshot.snapshot_digest,
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
    summary: {
      atomic_checks: checks.length,
      required: counts.REQUIRED,
      not_applicable: counts.NOT_APPLICABLE,
      unknown: counts.UNKNOWN,
      catalog_domain_required: checks.filter(check => check.subject_kind === "catalog-domain" && check.applicability === "REQUIRED").length,
      interface_required: checks.filter(check => check.subject_kind === "interface" && check.applicability === "REQUIRED").length,
    },
    complete: counts.UNKNOWN === 0 && inventoryBounded,
    claim_boundary: catalog.coverage_model.claim_boundary,
  };
  plan.manifest_digest = objectDigest(plan);
  const errors = validatePlan(plan);
  if (errors.length > 0) throw new Error(`Generated coverage plan is invalid:\n- ${errors.join("\n- ")}`);
  const output = resolve(args.output);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(plan, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output, manifest_digest: plan.manifest_digest, complete: plan.complete, ...plan.summary, universes: plan.universes })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
