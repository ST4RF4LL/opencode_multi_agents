import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import {
  buildExternalRuntimeValidationRequest,
  validateExternalRuntimeValidationRequest,
} from "../../skills/common-subagent/finding-evidence-contract/scripts/external-runtime-validation-contract.mjs";
import { webValidationCapability } from "./web-validation-policy.mjs";

const SAFE_ID = /^[A-Za-z0-9._-]{1,180}$/;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function latestRoundFile(directory, prefix, auditId) {
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); }
  catch (error) { if (error?.code === "ENOENT") return null; throw error; }
  const escaped = auditId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`^${prefix}\\.${escaped}\\.r(\\d+)\\.json$`);
  return entries
    .filter(entry => entry.isFile() && pattern.test(entry.name))
    .map(entry => ({ name: entry.name, round: Number(entry.name.match(pattern)[1]) }))
    .sort((left, right) => right.round - left.round)[0] ?? null;
}

async function readJsonBytes(path) {
  const bytes = await readFile(path);
  return { path, bytes, value: JSON.parse(bytes.toString("utf8")) };
}

async function writeExclusiveJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  try {
    await rename(temporary, path);
  } catch (error) {
    throw error;
  }
}

export async function materializeManualValidationRequests({ reportsRoot, auditId, repositoryId, commit }) {
  if (!SAFE_ID.test(auditId ?? "") || !SAFE_ID.test(repositoryId ?? "") || typeof commit !== "string" || !commit) {
    return { created: 0, eligible: 0, skipped: ["binding-invalid"] };
  }
  const adjudicationDirectory = join(reportsRoot, "adjudication");
  const [inputEntry, adjudicationEntry] = await Promise.all([
    latestRoundFile(adjudicationDirectory, "finding-input", auditId),
    latestRoundFile(adjudicationDirectory, "security-finding-adjudicator", auditId),
  ]);
  const finalModelPath = join(reportsRoot, "final", `security-audit-report-model.${auditId}.json`);
  if (!inputEntry || !adjudicationEntry) return { created: 0, eligible: 0, skipped: ["adjudication-artifacts-missing"] };

  let inputFile;
  let adjudicationFile;
  let finalModel;
  try {
    [inputFile, adjudicationFile, finalModel] = await Promise.all([
      readJsonBytes(join(adjudicationDirectory, inputEntry.name)),
      readJsonBytes(join(adjudicationDirectory, adjudicationEntry.name)),
      readJsonBytes(finalModelPath),
    ]);
  } catch (error) {
    if (error?.code === "ENOENT") return { created: 0, eligible: 0, skipped: ["final-artifacts-missing"] };
    throw error;
  }

  const finalFindingIds = new Set((finalModel.value.findings ?? [])
    .filter(finding => finding?.state === "TRUE_POSITIVE")
    .map(finding => finding.finding_id));
  const decisions = new Map((adjudicationFile.value.decisions ?? []).map((decision, index) => [decision.finding_id, { decision, index }]));
  const outputDirectory = join(reportsRoot, "validation-handoff", "runtime", auditId);
  let created = 0;
  let eligible = 0;
  const skipped = [];

  for (const candidate of inputFile.value.candidates ?? []) {
    const finding = candidate?.finding;
    const findingId = finding?.finding_id;
    if (!SAFE_ID.test(findingId ?? "") || !finalFindingIds.has(findingId)) continue;
    if (!await webValidationCapability(finding.classification?.vulnerability_type_id)) continue;
    const indexedDecision = decisions.get(findingId);
    if (!indexedDecision || !["SUPPORTED_STATIC", "INCONCLUSIVE"].includes(indexedDecision.decision.state)) continue;
    eligible += 1;
    const output = join(outputDirectory, `${findingId}.request.json`);
    try {
      const existing = JSON.parse(await readFile(output, "utf8"));
      if (validateExternalRuntimeValidationRequest(existing).length === 0) continue;
      skipped.push(`${findingId}:existing-request-invalid`);
      continue;
    } catch (error) {
      if (error?.code !== "ENOENT") { skipped.push(`${findingId}:existing-request-unreadable`); continue; }
    }
    try {
      const request = buildExternalRuntimeValidationRequest({
        requestId: `RVR-${auditId}-${findingId}`,
        finding,
        findingArtifact: { path: candidate.artifact?.path ?? inputFile.path, sha256: candidate.artifact?.sha256 ?? sha256(inputFile.bytes) },
        decision: indexedDecision.decision,
        adjudication: {
          path: adjudicationFile.path,
          sha256: sha256(adjudicationFile.bytes),
          json_pointer: `/decisions/${indexedDecision.index}`,
        },
        repository: { repository_id: repositoryId, commit },
        policy: {
          target_class: "ISOLATED_TEST_ENVIRONMENT",
          allowed_methods: ["BROWSER_TEST"],
          forbidden_actions: ["PRODUCTION_TARGET", "THIRD_PARTY_TARGET", "REAL_CREDENTIAL_USE", "PERSISTENCE", "DATA_DESTRUCTION"],
          safety_constraints: ["仅允许用户逐次授权的 loopback 测试环境和两个专用测试账号。"],
          network_access: "LOOPBACK_ONLY",
          credentials: "SYNTHETIC_ONLY",
        },
        proofGaps: indexedDecision.decision.blocking_questions?.length
          ? indexedDecision.decision.blocking_questions
          : ["尚未在用户逐次授权的 loopback 测试环境中观察运行时行为。"],
        exportedBySessionId: `workbench-manual-${auditId}-r${adjudicationEntry.round}`,
      });
      await writeExclusiveJson(output, request);
      created += 1;
    } catch (error) {
      skipped.push(`${findingId}:${error.message}`);
    }
  }
  return { created, eligible, skipped, output_directory: outputDirectory, source: basename(finalModelPath) };
}
