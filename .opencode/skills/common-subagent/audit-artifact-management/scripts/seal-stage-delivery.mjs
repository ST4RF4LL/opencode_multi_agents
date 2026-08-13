#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { stageDeliveryManifestDigest, validateStageDeliveryManifest } from "./stage-delivery-contract.mjs";
import { inspectStageDeliveryManifest, resolveReportsArtifact } from "./stage-delivery-materialization.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = resolve(HERE, "../contracts");

function argumentsMap(argv) {
  const result = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    if (!argv[index]?.startsWith("--") || argv[index + 1] === undefined) throw new Error("参数必须使用 --name value 形式。");
    result.set(argv[index].slice(2), argv[index + 1]);
  }
  return result;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requestPath(workspaceRoot, value) {
  const candidate = resolve(workspaceRoot, value);
  const rel = relative(workspaceRoot, candidate);
  if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error("request 路径越出工作区。");
  return candidate;
}

function mediaType(path) {
  if (extname(path) === ".md") return "text/markdown";
  if (extname(path) === ".sarif") return "application/sarif+json";
  if (extname(path) === ".jsonl") return "application/x-ndjson";
  return "application/json";
}

async function artifactBinding(reportsRoot, specification) {
  if (!specification || typeof specification.artifact_type !== "string" || typeof specification.path !== "string"
    || !(specification.json_pointer === null || (typeof specification.json_pointer === "string" && specification.json_pointer.startsWith("/")))) {
    throw new Error("artifact specification 无效。");
  }
  const path = resolveReportsArtifact(reportsRoot, specification.path);
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`制品不是普通文件：${specification.path}`);
  const bytes = await readFile(path);
  return {
    artifact_type: specification.artifact_type,
    path: specification.path,
    sha256: sha256(bytes),
    media_type: mediaType(specification.path),
    json_pointer: specification.json_pointer,
  };
}

async function predecessorCandidates(reportsRoot, auditId, stageId, maximumRound) {
  const directory = join(reportsRoot, "stage-deliveries", auditId);
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  const expression = new RegExp(`^${stageId.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.r([1-9][0-9]*)\\.json$`);
  return entries.filter(entry => entry.isFile() && expression.test(entry.name))
    .map(entry => ({ name: entry.name, round: Number(entry.name.match(expression)[1]) }))
    .filter(item => item.round <= maximumRound)
    .sort((left, right) => right.round - left.round);
}

async function bindPredecessor({ reportsRoot, auditId, stageId, maximumRound, registry, stageAgentRegistry, allowedStatuses }) {
  const candidates = await predecessorCandidates(reportsRoot, auditId, stageId, maximumRound);
  for (const candidate of candidates) {
    const path = `reports/stage-deliveries/${auditId}/${candidate.name}`;
    const inspected = await inspectStageDeliveryManifest({ reportsRoot, manifestPath: path, registry, stageAgentRegistry });
    if (!inspected.manifest || inspected.errors.length > 0 || !allowedStatuses.includes(inspected.manifest.status)) continue;
    return {
      stage_id: stageId,
      round: inspected.manifest.round,
      path,
      sha256: inspected.sha256,
      manifest_digest: inspected.manifest.manifest_digest,
      status: inspected.manifest.status,
    };
  }
  throw new Error(`缺少可绑定的前序 stage manifest：${stageId}`);
}

function completionSummary(manifest, stage, registry) {
  const active = conditionId => manifest.activated_conditions.includes(conditionId);
  const requiredOutputTypes = stage.output_artifacts
    .filter(item => item.requirement === "REQUIRED" || (item.requirement === "CONDITIONAL" && active(item.condition_id)))
    .map(item => item.artifact_type);
  const outputTypes = new Set(manifest.output_artifacts.map(item => item.artifact_type));
  const requiredValidatorIds = stage.validators
    .filter(item => item.requirement === "REQUIRED" || (item.requirement === "CONDITIONAL" && active(item.condition_id)))
    .map(item => item.validator_id);
  const validationById = new Map(manifest.validation_results.map(item => [item.validator_id, item.status]));
  const feedbackEdges = registry.feedback_edges.filter(edge => edge.to_stage_id === stage.stage_id && active(edge.condition_id));
  const requiredOutputsSatisfied = requiredOutputTypes.every(type => outputTypes.has(type));
  const requiredValidatorsPassed = requiredValidatorIds.every(id => validationById.get(id) === "PASS");
  const predecessorsComplete = stage.predecessor_stage_ids.every(id => manifest.predecessor_manifests.some(item => item.stage_id === id && item.status === "COMPLETE"))
    && feedbackEdges.every(edge => manifest.predecessor_manifests.some(item => item.stage_id === edge.from_stage_id && edge.allowed_source_statuses.includes(item.status)));
  return {
    required_outputs_satisfied: requiredOutputsSatisfied,
    required_validators_passed: requiredValidatorsPassed,
    predecessors_complete: predecessorsComplete,
    complete: requiredOutputsSatisfied && requiredValidatorsPassed
      && (!stage.completion_gate.requires_predecessors_complete || predecessorsComplete)
      && (!stage.completion_gate.requires_zero_gaps || manifest.gaps.length === 0),
  };
}

async function main() {
  const args = argumentsMap(process.argv.slice(2));
  if (!args.has("request")) throw new Error("缺少 --request。");
  const workspaceRoot = resolve(process.env.AUDIT_WORKSPACE_ROOT ?? process.cwd());
  const reportsRoot = resolve(process.env.AUDIT_REPORTS_ROOT ?? join(workspaceRoot, "reports"));
  const [registry, stageAgentRegistry, request] = await Promise.all([
    readFile(join(CONTRACTS, "workbench-stage-deliveries.json"), "utf8").then(JSON.parse),
    readFile(join(CONTRACTS, "stage-agent-contracts.json"), "utf8").then(JSON.parse),
    readFile(requestPath(workspaceRoot, args.get("request")), "utf8").then(JSON.parse),
  ]);
  const expectedFields = ["stage_id", "audit_id", "round", "status", "scope_digest", "activated_conditions", "input_artifacts", "output_artifacts", "validation_results", "gaps", "producer", "started_at", "completed_at"];
  if (!request || Object.keys(request).length !== expectedFields.length || expectedFields.some(key => !Object.hasOwn(request, key))) {
    throw new Error("stage seal request 字段不完整或包含额外字段。");
  }
  const stage = registry.stages.find(item => item.stage_id === request.stage_id);
  if (!stage) throw new Error(`未知工作台 stage：${request.stage_id}`);
  const feedbackEdges = registry.feedback_edges.filter(edge => edge.to_stage_id === stage.stage_id && request.activated_conditions.includes(edge.condition_id));
  const predecessors = [];
  for (const predecessorId of stage.predecessor_stage_ids) predecessors.push(await bindPredecessor({
    reportsRoot, auditId: request.audit_id, stageId: predecessorId, maximumRound: request.round,
    registry, stageAgentRegistry, allowedStatuses: ["COMPLETE"],
  }));
  for (const edge of feedbackEdges) predecessors.push(await bindPredecessor({
    reportsRoot, auditId: request.audit_id, stageId: edge.from_stage_id, maximumRound: request.round - 1,
    registry, stageAgentRegistry, allowedStatuses: edge.allowed_source_statuses,
  }));
  const manifest = {
    schema_version: 1,
    registry_id: registry.registry_id,
    registry_digest: registry.registry_digest,
    template_id: stage.template_id,
    stage_id: stage.stage_id,
    stage_order: stage.order,
    audit_id: request.audit_id,
    round: request.round,
    status: request.status,
    scope_binding: { state: "FROZEN", scope_digest: request.scope_digest },
    activated_conditions: request.activated_conditions,
    predecessor_manifests: predecessors,
    input_artifacts: await Promise.all(request.input_artifacts.map(item => artifactBinding(reportsRoot, item))),
    output_artifacts: await Promise.all(request.output_artifacts.map(item => artifactBinding(reportsRoot, item))),
    validation_results: request.validation_results,
    gaps: request.gaps,
    producer: request.producer,
    started_at: request.started_at,
    completed_at: request.completed_at,
    completion: null,
  };
  manifest.completion = completionSummary(manifest, stage, registry);
  manifest.manifest_digest = stageDeliveryManifestDigest(manifest);
  const errors = validateStageDeliveryManifest(manifest, registry, { stageAgentRegistry });
  if (errors.length > 0) throw new Error(`stage manifest 结构无效：${errors.join(", ")}`);
  const relativePath = registry.manifest.path_template
    .replaceAll("{audit_id}", request.audit_id).replaceAll("{stage_id}", request.stage_id).replaceAll("{round}", String(request.round));
  const outputPath = resolveReportsArtifact(reportsRoot, relativePath);
  await mkdir(dirname(outputPath), { recursive: true });
  try {
    const existing = JSON.parse(await readFile(outputPath, "utf8"));
    if (existing.status === "COMPLETE" && existing.manifest_digest !== manifest.manifest_digest) {
      throw new Error("已存在不同摘要的 COMPLETE stage manifest；请增加 round，不能静默覆盖。");
    }
  } catch (error) {
    if (error?.code !== "ENOENT" && !String(error.message).includes("Unexpected")) throw error;
  }
  const temporary = `${outputPath}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(manifest, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporary, outputPath);
  const materialized = await inspectStageDeliveryManifest({ reportsRoot, manifestPath: relativePath, registry, stageAgentRegistry });
  if (!materialized.complete) throw new Error(`stage manifest 物化校验失败：${materialized.errors.join(", ")}`);
  process.stdout.write(`${JSON.stringify({ complete: true, stage_id: request.stage_id, round: request.round, path: relativePath, manifest_digest: manifest.manifest_digest })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
