import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import { extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { renderFinalReport, validateFinalReportModel } from "../../skills/common-subagent/audit-coverage-accounting/scripts/final-report-model-core.mjs";
import { verifyAuditStageDeliveries } from "../../skills/common-subagent/audit-artifact-management/scripts/stage-delivery-materialization.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const STAGE_DELIVERY_REGISTRY = resolve(HERE, "../../skills/common-subagent/audit-artifact-management/contracts/workbench-stage-deliveries.json");
const STAGE_AGENT_REGISTRY = resolve(HERE, "../../skills/common-subagent/audit-artifact-management/contracts/stage-agent-contracts.json");

const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;
const MAX_ARTIFACTS = 5000;
const REPORT_EXTENSIONS = new Set([".json", ".md", ".sarif"]);
const REPORT_DIRECTORIES = new Set([
  "adjudication",
  "attack-chains",
  "checkpoints",
  "correlation",
  "coverage",
  "final",
  "sarif",
  "stage-deliveries",
  "validation",
  "vulnerability-mining",
]);

const STAGES = [
  { id: "scope", label: "范围冻结" },
  { id: "recon", label: "资产侦察" },
  { id: "threat", label: "威胁建模" },
  { id: "audit", label: "多维漏洞审计" },
  { id: "correlation", label: "证据关联" },
  { id: "adjudication", label: "发现裁决" },
  { id: "validation", label: "验证复核" },
  { id: "report", label: "报告封存" },
];

function safeRelative(root, candidate) {
  const absoluteRoot = resolve(root);
  const absolute = resolve(candidate);
  const value = relative(absoluteRoot, absolute);
  if (value.startsWith("..") || isAbsolute(value) || value.split(sep).includes("..")) return null;
  return value;
}

function normalizedPath(root, candidate) {
  const value = safeRelative(root, candidate);
  return value === null ? null : value.split(sep).join("/");
}

async function collectFiles(root, current = root, depth = 0, output = []) {
  if (output.length >= MAX_ARTIFACTS || depth > 4) return output;
  let entries;
  try {
    entries = await readdir(current, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") return output;
    throw error;
  }
  for (const entry of entries) {
    if (output.length >= MAX_ARTIFACTS) break;
    if (entry.name.startsWith(".")) continue;
    const path = join(current, entry.name);
    if (entry.isDirectory()) {
      await collectFiles(root, path, depth + 1, output);
    } else if (entry.isFile() && REPORT_EXTENSIONS.has(extname(entry.name))) {
      output.push(path);
    }
  }
  return output;
}

async function readJsonArtifact(path, info) {
  if (info.size > MAX_ARTIFACT_BYTES) return null;
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return null;
  }
}

function auditIdFromFileName(fileName) {
  const patterns = [
    /^security-audit-report\.(.+)\.md$/,
    /^coverage-(?:plan|summary|verification|structural-v1)\.(.+)\.(?:json|md)$/,
    /^semantic-coverage-verification\.(.+)\.json$/,
    /^vuln-judger-review\.(.+)\.(?:json|md)$/,
  ];
  for (const pattern of patterns) {
    const match = fileName.match(pattern);
    if (match) return match[1];
  }
  return null;
}

function artifactKind(path) {
  const first = path.split("/")[0];
  return REPORT_DIRECTORIES.has(first) ? first : "other";
}

export async function scanReportArtifacts(reportsRoot) {
  const root = resolve(reportsRoot);
  const files = await collectFiles(root);
  const artifacts = [];
  for (const path of files) {
    const rel = normalizedPath(root, path);
    if (!rel) continue;
    const info = await stat(path);
    const extension = extname(path);
    const data = extension === ".json" || extension === ".sarif" ? await readJsonArtifact(path, info) : null;
    const auditId = typeof data?.audit_id === "string" ? data.audit_id : auditIdFromFileName(path.split(sep).at(-1));
    if (!auditId) continue;
    const kind = artifactKind(rel);
    const markdownBytes = kind === "final" && extension === ".md" && info.size <= MAX_ARTIFACT_BYTES ? await readFile(path) : null;
    const markdown = markdownBytes === null ? null : markdownBytes.toString("utf8");
    const sha256 = markdownBytes === null ? null : createHash("sha256").update(markdownBytes).digest("hex");
    artifacts.push({
      id: createHash("sha256").update(rel).digest("hex").slice(0, 24),
      audit_id: auditId,
      kind,
      path: rel,
      media_type: extension === ".md" ? "text/markdown" : extension === ".sarif" ? "application/sarif+json" : "application/json",
      size: info.size,
      modified_at: info.mtime.toISOString(),
      sha256,
      data,
      markdown,
    });
  }
  return artifacts.sort((left, right) => right.modified_at.localeCompare(left.modified_at));
}

function hasArtifact(artifacts, kind, fragment = null) {
  return artifacts.some(artifact => artifact.kind === kind && (!fragment || artifact.path.includes(fragment)));
}

function stageSnapshot(artifacts, runtimeCount, materialized = null) {
  if (materialized) return materialized.stages.map(stage => ({
    id: stage.id,
    label: stage.label,
    state: stage.state,
    round: stage.round,
    manifest_path: stage.manifest_path,
    manifest_digest: stage.manifest_digest,
    issues: stage.errors,
  }));
  const reached = {
    scope: hasArtifact(artifacts, "coverage", "coverage-plan."),
    recon: hasArtifact(artifacts, "coverage", "coverage-plan."),
    threat: hasArtifact(artifacts, "coverage", "coverage-plan."),
    audit: hasArtifact(artifacts, "vulnerability-mining"),
    correlation: hasArtifact(artifacts, "correlation"),
    adjudication: hasArtifact(artifacts, "adjudication"),
    validation: hasArtifact(artifacts, "validation") || runtimeCount > 0,
    report: hasArtifact(artifacts, "final"),
  };
  let contiguousReached = -1;
  for (let index = 0; index < STAGES.length && reached[STAGES[index].id]; index += 1) contiguousReached = index;
  const hasOutOfOrderEvidence = STAGES.some((stage, index) => index > contiguousReached + 1 && reached[stage.id]);
  const activeIndex = hasOutOfOrderEvidence ? -1 : contiguousReached + 1;
  return STAGES.map((stage, index) => ({
    ...stage,
    state: reached[stage.id] ? "completed" : index === activeIndex ? "active" : "pending",
  }));
}

function coverageFromArtifacts(artifacts) {
  const summary = artifacts.find(artifact => artifact.path.includes("coverage-summary.") && artifact.media_type === "application/json")?.data;
  if (!summary) return null;
  return {
    status: summary.coverage_status ?? (summary.complete ? "COMPLETE" : "UNKNOWN"),
    complete: summary.complete === true,
    files: summary.inventory?.files ?? summary.files?.complete_entities ?? null,
    functions: summary.functions?.complete_entities ?? null,
    vulnerability_types: summary.vulnerability_types?.fully_checked ?? summary.vulnerability_types?.checks ?? null,
    external_interfaces: summary.external_interfaces?.complete_entities ?? null,
    manifest_digest: summary.manifest_digest ?? null,
  };
}

function severityRank(value) {
  return ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 })[String(value ?? "").toUpperCase()] ?? -1;
}

function displayText(value, limit = 4000) {
  const text = Array.isArray(value)
    ? value.map(item => typeof item === "string" ? item : item?.description ?? item?.summary ?? "").filter(Boolean).join("\n")
    : typeof value === "string"
      ? value
      : value?.summary ?? value?.description ?? null;
  if (!text) return null;
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}

function normalizedLocations(raw) {
  let values = raw.locations ?? raw.affected_locations ?? raw.additional_locations ?? (raw.primary_location ? [raw.primary_location] : []);
  if (!Array.isArray(values)) values = [values];
  if (values.length === 0 && (raw.file || raw.location)) {
    values = [typeof raw.location === "object" ? raw.location : {
      path: raw.file,
      line: raw.line_start ?? raw.line,
      line_end: raw.line_end,
      detail: typeof raw.location === "string" ? raw.location : raw.lines,
    }];
  }
  return values.slice(0, 20).map(location => ({
    path: location?.path ?? location?.file ?? null,
    line: location?.line ?? location?.line_start ?? null,
    line_end: location?.line_end ?? null,
    detail: displayText(location?.detail ?? location?.description ?? location?.snippet, 1000),
  })).filter(location => location.path || location.detail);
}

function normalizeFinding(raw, auditId, sourcePath) {
  const locations = normalizedLocations(raw);
  const location = locations[0] ?? {};
  return {
    id: raw.canonical_id ?? raw.finding_id ?? raw.id ?? createHash("sha256").update(`${auditId}:${sourcePath}:${raw.title ?? "finding"}`).digest("hex").slice(0, 16),
    audit_id: auditId,
    title: raw.title ?? raw.summary ?? "未命名漏洞发现",
    severity: String(raw.severity ?? "UNKNOWN").toUpperCase(),
    cvss_score: raw.cvss_score ?? raw.cvss?.score ?? null,
    status: raw.validation_state ?? raw.status ?? "unvalidated",
    dimension: raw.dimension ?? null,
    vulnerability_type_id: raw.vulnerability_type_id ?? raw.cwe ?? null,
    description: displayText(raw.description ?? raw.summary),
    location,
    locations,
    remediation: displayText(raw.remediation),
    residual_uncertainty: displayText(raw.residual_uncertainty),
    source_finding_ids: (raw.source_findings ?? []).slice(0, 32).map(item => item?.finding_id ?? item?.id).filter(Boolean),
    contradiction_count: Array.isArray(raw.contradictions) ? raw.contradictions.length : 0,
    source_path: sourcePath,
  };
}

export function findingsFromArtifacts(artifacts) {
  const byAudit = new Map();
  for (const artifact of artifacts.filter(item => item.kind === "correlation")) {
    if (byAudit.has(artifact.audit_id)) continue;
    const findings = Array.isArray(artifact.data?.canonical_findings) ? artifact.data.canonical_findings : [];
    if (findings.length) byAudit.set(artifact.audit_id, findings.map(item => normalizeFinding(item, artifact.audit_id, artifact.path)));
  }
  for (const artifact of artifacts.filter(item => item.kind === "vulnerability-mining")) {
    if (byAudit.has(artifact.audit_id)) continue;
    const current = byAudit.get(artifact.audit_id) ?? [];
    for (const item of artifact.data?.findings ?? []) current.push(normalizeFinding(item, artifact.audit_id, artifact.path));
    byAudit.set(artifact.audit_id, current);
  }
  const seen = new Set();
  return [...byAudit.values()].flat().filter(finding => {
    const key = `${finding.audit_id}:${finding.id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((left, right) => severityRank(right.severity) - severityRank(left.severity));
}

function reportFromArtifact(artifact, artifacts) {
  const model = artifacts.find(item => item.path === `final/security-audit-report-model.${artifact.audit_id}.json`)?.data ?? null;
  let integrityState = "digest_only";
  let integrityIssues = [];
  if (model) {
    try {
      integrityIssues = validateFinalReportModel(model);
      if (model.audit_id !== artifact.audit_id) integrityIssues.push("final-report-model-audit-mismatch");
      if (integrityIssues.length === 0 && artifact.markdown !== renderFinalReport(model)) integrityIssues.push("final-report-not-deterministic-render");
      integrityIssues = [...new Set(integrityIssues)];
      integrityState = integrityIssues.length === 0 ? "verified_model" : "model_mismatch";
    } catch {
      integrityState = "model_mismatch";
      integrityIssues = ["final-report-model-verification-error"];
    }
  }
  return {
    id: artifact.id,
    audit_id: artifact.audit_id,
    name: `安全审计报告 · ${artifact.audit_id}`,
    path: artifact.path,
    size: artifact.size,
    sealed_at: artifact.modified_at,
    media_type: artifact.media_type,
    sha256: artifact.sha256,
    integrity_state: integrityState,
    integrity_issues: integrityIssues,
    model_digest: typeof model?.manifest_digest === "string" ? model.manifest_digest : null,
  };
}

export function auditsFromArtifacts(artifacts, validationRuns = [], runnerAudits = [], stageDeliveriesByAudit = new Map()) {
  const groups = new Map();
  for (const artifact of artifacts) {
    const current = groups.get(artifact.audit_id) ?? [];
    current.push(artifact);
    groups.set(artifact.audit_id, current);
  }
  for (const run of validationRuns) if (!groups.has(run.audit_id)) groups.set(run.audit_id, []);
  for (const run of runnerAudits) if (!groups.has(run.id)) groups.set(run.id, []);
  const runnerById = new Map(runnerAudits.map(run => [run.id, run]));
  const findings = findingsFromArtifacts(artifacts);
  return [...groups.entries()].map(([auditId, auditArtifacts]) => {
    const runtimeCount = validationRuns.filter(run => run.audit_id === auditId).length;
    const runner = runnerById.get(auditId);
    const materialized = stageDeliveriesByAudit.get(auditId);
    const useMaterialized = Boolean(materialized && (runner?.stage_delivery_enforcement === "ENFORCED"
      || materialized.completed_count > 0 || auditArtifacts.some(artifact => artifact.kind === "stage-deliveries")));
    const stages = stageSnapshot(auditArtifacts, runtimeCount, useMaterialized ? materialized : null);
    const lastModified = auditArtifacts.map(item => item.modified_at).sort().at(-1) ?? runner?.updated_at ?? null;
    const completedCount = stages.filter(stage => stage.state === "completed").length;
    const completed = completedCount === stages.length;
    const progress = Math.round((completedCount / stages.length) * 100);
    const activeStage = stages.find(stage => stage.state === "active");
    const discontinuous = !activeStage && !completed && completedCount > 0;
    return {
      id: auditId,
      name: runner?.name ?? `仓库级安全审计 · ${auditId}`,
      repository_id: runner?.repository_id ?? null,
      repository_name: runner?.repository_name ?? null,
      commit: runner?.commit ?? null,
      status: runner?.status ?? (completed ? "completed" : "artifact_only"),
      version: runner?.version ?? 1,
      event_sequence: runner?.event_sequence ?? 0,
      stage: activeStage?.label ?? (discontinuous ? "制品不连续" : completed ? "报告封存" : "等待开始"),
      stages,
      progress,
      progress_source: useMaterialized ? "stage-delivery-manifest" : "legacy-artifact-heuristic",
      finding_count: findings.filter(finding => finding.audit_id === auditId).length,
      runtime_validation_count: runtimeCount,
      artifact_count: auditArtifacts.length,
      coverage: coverageFromArtifacts(auditArtifacts),
      created_at: runner?.created_at ?? lastModified,
      updated_at: runner?.updated_at ?? lastModified,
      exit_code: runner?.exit_code ?? null,
      error: runner?.error ?? null,
      execution_transport: runner?.execution_transport ?? null,
      terminal: runner?.terminal ?? null,
      paths: runner?.paths ?? null,
      provider_session_id: runner?.provider_session_id ?? runner?.terminal?.provider_session_id ?? null,
      recovery_count: Number(runner?.recovery_count ?? 0),
      last_recovered_at: runner?.last_recovered_at ?? null,
      interrupted_at: runner?.interrupted_at ?? null,
      interruption_reason: runner?.interruption_reason ?? null,
      task_context: runner?.task_context ?? {
        additional_instructions_enabled: false,
        additional_instructions_length: 0,
        test_environment_enabled: false,
        test_environment_length: 0,
        dynamic_validation_enabled: false,
      },
    };
  }).sort((left, right) => String(right.updated_at ?? "").localeCompare(String(left.updated_at ?? "")));
}

export async function buildWorkspaceSnapshot({ reportsRoot, validationRuns = [], runnerAudits = [] }) {
  const artifacts = await scanReportArtifacts(reportsRoot);
  const findings = findingsFromArtifacts(artifacts);
  const auditIds = new Set([
    ...artifacts.map(artifact => artifact.audit_id),
    ...validationRuns.map(run => run.audit_id),
    ...runnerAudits.map(run => run.id),
  ]);
  const [registry, stageAgentRegistry] = await Promise.all([
    readFile(STAGE_DELIVERY_REGISTRY, "utf8").then(JSON.parse),
    readFile(STAGE_AGENT_REGISTRY, "utf8").then(JSON.parse),
  ]);
  const stageDeliveriesByAudit = new Map(await Promise.all([...auditIds].map(async auditId => [
    auditId,
    await verifyAuditStageDeliveries({ reportsRoot, auditId, registry, stageAgentRegistry }),
  ])));
  const audits = auditsFromArtifacts(artifacts, validationRuns, runnerAudits, stageDeliveriesByAudit);
  const reports = artifacts.filter(artifact => artifact.kind === "final" && artifact.media_type === "text/markdown").map(artifact => reportFromArtifact(artifact, artifacts));
  const severity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const finding of findings) {
    const key = finding.severity.toLowerCase();
    severity[key in severity ? key : "unknown"] += 1;
  }
  return {
    generated_at: new Date().toISOString(),
    summary: {
      audit_count: audits.length,
      active_audits: audits.filter(audit => ["queued", "preparing", "recovering", "running", "pausing", "paused", "cancelling"].includes(audit.status)).length,
      completed_audits: audits.filter(audit => audit.status === "completed").length,
      finding_count: findings.length,
      report_count: reports.length,
      validation_run_count: validationRuns.length,
      severity,
    },
    audits,
    findings,
    reports,
    artifacts: artifacts.map(({ data, markdown, ...metadata }) => metadata),
  };
}
