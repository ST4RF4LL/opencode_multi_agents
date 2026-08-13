import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { validateStageDeliveryManifest } from "./stage-delivery-contract.mjs";
import { validateArtifactSetIndex } from "./artifact-set-contract.mjs";
import { validateAdjudicationManifest, validateCandidateManifest } from "../../finding-adjudication/scripts/finding-adjudication-contract.mjs";
import { validateCvssAssessmentManifest } from "../../finding-adjudication/scripts/cvss-assessment-contract.mjs";
import { validateAttackChainManifest } from "../../../attack-chain-subagent/system-attack-chain-hunting/scripts/attack-chain-contract.mjs";
import { validateTruthValidationBundle } from "../../../vulnerability-validator-subagent/vulnerability-validation/scripts/truth-validation-contract.mjs";
import { renderFinalReport, validateFinalReportModel } from "../../audit-coverage-accounting/scripts/final-report-model-core.mjs";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function controlledRelative(root, candidate) {
  const rel = relative(resolve(root), resolve(candidate));
  return rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

export function resolveReportsArtifact(reportsRoot, artifactPath) {
  if (typeof artifactPath !== "string" || !artifactPath.startsWith("reports/") || artifactPath.split("/").includes("..")) {
    throw new Error(`stage-delivery-artifact-path-invalid:${artifactPath ?? ""}`);
  }
  const candidate = resolve(reportsRoot, artifactPath.slice("reports/".length));
  if (!controlledRelative(reportsRoot, candidate)) throw new Error(`stage-delivery-artifact-path-escape:${artifactPath}`);
  return candidate;
}

async function materializedFile(reportsRoot, artifactPath, expectedDigest) {
  try {
    const candidate = resolveReportsArtifact(reportsRoot, artifactPath);
    const info = await lstat(candidate);
    if (!info.isFile() || info.isSymbolicLink()) return { ok: false, error: `artifact-not-regular-file:${artifactPath}` };
    const [rootReal, candidateReal, bytes] = await Promise.all([realpath(reportsRoot), realpath(candidate), readFile(candidate)]);
    if (!controlledRelative(rootReal, candidateReal)) return { ok: false, error: `artifact-realpath-escape:${artifactPath}` };
    const actualDigest = sha256(bytes);
    if (expectedDigest && actualDigest !== expectedDigest) return { ok: false, error: `artifact-sha256-mismatch:${artifactPath}` };
    return { ok: true, path: candidate, bytes, sha256: actualDigest };
  } catch (error) {
    return { ok: false, error: `${error?.code === "ENOENT" ? "artifact-missing" : "artifact-read-failed"}:${artifactPath}` };
  }
}

function parsedJson(file, artifactType, errors) {
  if (!file?.ok) return null;
  try {
    return JSON.parse(file.bytes.toString("utf8"));
  } catch {
    errors.push(`artifact-json-invalid:${artifactType}`);
    return null;
  }
}

async function validateArtifactSetMaterialization({ reportsRoot, binding, file, manifest, errors }) {
  const index = parsedJson(file, binding.artifact_type, errors);
  if (!index) return;
  const indexErrors = validateArtifactSetIndex(index, {
    expectedSetType: binding.artifact_type,
    auditId: manifest.audit_id,
    round: manifest.round,
    scopeDigest: manifest.scope_binding?.scope_digest,
  });
  errors.push(...indexErrors.map(error => `${binding.artifact_type}:${error}`));
  if (indexErrors.length > 0) return;
  for (const item of index.items) {
    const member = await materializedFile(reportsRoot, item.path, item.sha256);
    if (!member.ok) errors.push(`${binding.artifact_type}:member-${member.error}`);
  }
}

export async function validateQuickEvidenceMaterialization({ reportsRoot, file, errors }) {
  const resultSet = parsedJson(file, "quick-dynamic-result-set", errors);
  if (!resultSet || !Array.isArray(resultSet.evidence_bindings)) return;
  for (const binding of resultSet.evidence_bindings) {
    const evidence = await materializedFile(reportsRoot, binding.path, binding.sha256);
    if (!evidence.ok) errors.push(`quick-dynamic-evidence:${evidence.error}`);
  }
}

function validateKnownStageContracts(stageId, artifacts, errors) {
  const json = artifactType => parsedJson(artifacts.get(artifactType), artifactType, errors);
  if (stageId === "adjudication") {
    const input = json("finding-adjudication-input");
    const adjudication = json("finding-adjudication");
    if (input) errors.push(...validateCandidateManifest(input).map(error => `finding-adjudication-input:${error}`));
    if (input && adjudication) errors.push(...validateAdjudicationManifest(adjudication, input).map(error => `finding-adjudication:${error}`));
  }
  if (stageId === "validation") {
    const input = json("finding-adjudication-input");
    const adjudication = json("finding-adjudication");
    const bundle = {
      intake: json("truth-validation-intake"),
      quickResultSet: json("quick-dynamic-result-set"),
      affirmative: json("affirmative-review"),
      negative: json("negative-review"),
      moderator: json("moderator-review"),
      routing: json("validation-routing-manifest"),
    };
    if (Object.values(bundle).every(Boolean)) {
      errors.push(...validateTruthValidationBundle(bundle).map(error => `truth-validation:${error}`));
    }
    if (input) errors.push(...validateCandidateManifest(input).map(error => `finding-adjudication-input:${error}`));
    if (input && adjudication) errors.push(...validateAdjudicationManifest(adjudication, input).map(error => `finding-adjudication:${error}`));
    if (adjudication && bundle.routing) {
      const cvss = json("cvss-assessment");
      const chains = json("attack-chain-report");
      if (cvss) errors.push(...validateCvssAssessmentManifest(cvss, adjudication, bundle.routing).map(error => `cvss-assessment:${error}`));
      if (chains) errors.push(...validateAttackChainManifest(chains, adjudication, bundle.routing).map(error => `attack-chain:${error}`));
    }
  }
  if (stageId === "report") {
    const model = json("final-report-model");
    const markdownFile = artifacts.get("final-report");
    if (model) errors.push(...validateFinalReportModel(model).map(error => `final-report-model:${error}`));
    if (model && markdownFile?.ok && markdownFile.bytes.toString("utf8") !== renderFinalReport(model)) {
      errors.push("final-report-not-deterministic-render");
    }
    const routing = json("validation-routing-manifest");
    if (model && routing && model.truth_validation?.routing_digest !== routing.artifact_digest) {
      errors.push("final-report-routing-binding-mismatch");
    }
  }
}

function stageManifestRelativePath(registry, auditId, stageId, round) {
  return registry.manifest.path_template
    .replaceAll("{audit_id}", auditId)
    .replaceAll("{stage_id}", stageId)
    .replaceAll("{round}", String(round));
}

async function inspectManifestInternal({ reportsRoot, manifestPath, registry, stageAgentRegistry, cache, stack }) {
  const relativePath = manifestPath.startsWith("reports/")
    ? manifestPath
    : `reports/${relative(resolve(reportsRoot), resolve(manifestPath)).split(sep).join("/")}`;
  if (cache.has(relativePath)) return cache.get(relativePath);
  if (stack.has(relativePath)) return { complete: false, manifest: null, path: relativePath, errors: [`predecessor-cycle:${relativePath}`] };
  stack.add(relativePath);
  const errors = [];
  const ownFile = await materializedFile(reportsRoot, relativePath);
  if (!ownFile.ok) {
    const result = { complete: false, manifest: null, path: relativePath, errors: [ownFile.error] };
    stack.delete(relativePath);
    cache.set(relativePath, result);
    return result;
  }
  let manifest;
  try {
    manifest = JSON.parse(ownFile.bytes.toString("utf8"));
  } catch {
    const result = { complete: false, manifest: null, path: relativePath, errors: [`manifest-json-invalid:${relativePath}`] };
    stack.delete(relativePath);
    cache.set(relativePath, result);
    return result;
  }
  errors.push(...validateStageDeliveryManifest(manifest, registry, { stageAgentRegistry }));
  const expectedPath = stageManifestRelativePath(registry, manifest.audit_id, manifest.stage_id, manifest.round);
  if (relativePath !== expectedPath) errors.push(`manifest-path-mismatch:${relativePath}`);

  const stage = registry.stages.find(item => item.stage_id === manifest.stage_id);
  const artifactFiles = new Map();
  for (const binding of [...(manifest.input_artifacts ?? []), ...(manifest.output_artifacts ?? [])]) {
    const file = await materializedFile(reportsRoot, binding.path, binding.sha256);
    if (!file.ok) errors.push(file.error);
    else artifactFiles.set(binding.artifact_type, file);
    const template = [...(stage?.input_artifacts ?? []), ...(stage?.output_artifacts ?? [])]
      .find(item => item.artifact_type === binding.artifact_type);
    if (file.ok && template?.contract_ref?.endsWith("artifact-set-index-v1.schema.json")) {
      await validateArtifactSetMaterialization({ reportsRoot, binding, file, manifest, errors });
    }
    if (file.ok && binding.artifact_type === "quick-dynamic-result-set") {
      await validateQuickEvidenceMaterialization({ reportsRoot, file, errors });
    }
  }

  const predecessorResults = new Map();
  for (const predecessor of manifest.predecessor_manifests ?? []) {
    const file = await materializedFile(reportsRoot, predecessor.path, predecessor.sha256);
    if (!file.ok) {
      errors.push(`predecessor-${file.error}`);
      continue;
    }
    let predecessorManifest;
    try { predecessorManifest = JSON.parse(file.bytes.toString("utf8")); } catch { errors.push(`predecessor-json-invalid:${predecessor.path}`); continue; }
    if (predecessorManifest.manifest_digest !== predecessor.manifest_digest
      || predecessorManifest.stage_id !== predecessor.stage_id
      || predecessorManifest.round !== predecessor.round
      || predecessorManifest.status !== predecessor.status
      || predecessorManifest.audit_id !== manifest.audit_id) errors.push(`predecessor-binding-mismatch:${predecessor.path}`);
    const inspected = await inspectManifestInternal({
      reportsRoot,
      manifestPath: predecessor.path,
      registry,
      stageAgentRegistry,
      cache,
      stack,
    });
    predecessorResults.set(predecessor.stage_id, inspected);
    if (!inspected.complete && predecessor.status === "COMPLETE") errors.push(`predecessor-materialization-invalid:${predecessor.path}`);
  }

  for (const binding of manifest.input_artifacts ?? []) {
    const template = stage?.input_artifacts.find(item => item.artifact_type === binding.artifact_type);
    for (const sourceStageId of template?.source_stage_ids ?? []) {
      const predecessor = predecessorResults.get(sourceStageId)?.manifest;
      const matched = predecessor?.output_artifacts?.some(output => output.artifact_type === binding.artifact_type
        && output.path === binding.path && output.sha256 === binding.sha256 && output.json_pointer === binding.json_pointer);
      if (!matched) errors.push(`input-provenance-mismatch:${binding.artifact_type}:${sourceStageId}`);
    }
  }

  for (const validation of manifest.validation_results ?? []) {
    if (validation.status !== "PASS") continue;
    if (!Array.isArray(validation.evidence_refs) || validation.evidence_refs.length === 0) {
      errors.push(`validation-pass-evidence-missing:${validation.validator_id}`);
      continue;
    }
    for (const evidenceRef of validation.evidence_refs) {
      if (!evidenceRef.startsWith("reports/")) {
        errors.push(`validation-evidence-path-invalid:${validation.validator_id}`);
        continue;
      }
      const evidence = await materializedFile(reportsRoot, evidenceRef);
      if (!evidence.ok) errors.push(`validation-${evidence.error}`);
    }
  }
  validateKnownStageContracts(manifest.stage_id, artifactFiles, errors);
  const result = {
    complete: errors.length === 0 && manifest.status === "COMPLETE" && manifest.completion?.complete === true,
    manifest,
    path: relativePath,
    sha256: ownFile.sha256,
    errors: [...new Set(errors)],
  };
  stack.delete(relativePath);
  cache.set(relativePath, result);
  return result;
}

export async function inspectStageDeliveryManifest({ reportsRoot, manifestPath, registry, stageAgentRegistry = null }) {
  return inspectManifestInternal({
    reportsRoot: resolve(reportsRoot),
    manifestPath,
    registry,
    stageAgentRegistry,
    cache: new Map(),
    stack: new Set(),
  });
}

async function stageManifestCandidates(reportsRoot, auditId, stageId) {
  const directory = join(resolve(reportsRoot), "stage-deliveries", auditId);
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  const expression = new RegExp(`^${stageId.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.r([1-9][0-9]*)\\.json$`);
  return entries
    .filter(entry => entry.isFile() && expression.test(entry.name))
    .map(entry => ({
      path: `reports/stage-deliveries/${auditId}/${entry.name}`,
      round: Number(entry.name.match(expression)[1]),
    }))
    .sort((left, right) => right.round - left.round);
}

export async function verifyAuditStageDeliveries({ reportsRoot, auditId, registry, stageAgentRegistry = null }) {
  const stages = [];
  let priorComplete = true;
  for (const stage of registry.stages) {
    const candidates = await stageManifestCandidates(reportsRoot, auditId, stage.stage_id);
    const inspected = [];
    for (const candidate of candidates) {
      inspected.push(await inspectStageDeliveryManifest({
        reportsRoot,
        manifestPath: candidate.path,
        registry,
        stageAgentRegistry,
      }));
    }
    const selected = inspected.find(item => item.complete) ?? null;
    const errors = selected ? [] : inspected.flatMap(item => item.errors);
    const complete = Boolean(selected) && priorComplete;
    stages.push({
      id: stage.stage_id,
      label: stage.label,
      order: stage.order,
      state: complete ? "completed" : priorComplete ? "active" : "pending",
      round: selected?.manifest?.round ?? null,
      manifest_path: selected?.path ?? candidates[0]?.path ?? null,
      manifest_digest: selected?.manifest?.manifest_digest ?? null,
      errors: [...new Set(errors)],
    });
    if (!complete) priorComplete = false;
  }
  const complete = stages.length === 8 && stages.every(stage => stage.state === "completed");
  return {
    enforcement: registry.lifecycle?.enforcement ?? null,
    audit_id: auditId,
    complete,
    completed_count: stages.filter(stage => stage.state === "completed").length,
    stages,
    errors: stages.flatMap(stage => stage.errors.map(error => `${stage.id}:${error}`)),
  };
}
