import { createHash } from "node:crypto";

export const LENSES = ["sink-driven", "control-driven", "config-driven"];
export const DIMENSIONS = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);
export const MACHINE_COVERAGE_SCHEMA_VERSION = 1;

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function catalogQuestionDigest(entry, lens) {
  const prefix = lens?.split("-")[0];
  return sha256(`${entry.id}\n${lens}\n${entry[`${prefix}_question`] ?? ""}`);
}

function exactUniqueIds(value, label) {
  if (!Array.isArray(value) || value.some(id => typeof id !== "string" || !id) || new Set(value).size !== value.length) {
    throw new Error(`${label} must be an array of unique non-empty IDs`);
  }
  return value;
}

function recordMap(records, idField, label) {
  if (!Array.isArray(records)) throw new Error(`${label} coverage must be an array`);
  const mapped = new Map();
  for (const record of records) {
    const id = record?.[idField];
    if (typeof id !== "string" || !id) throw new Error(`${label} coverage has an invalid ${idField}`);
    if (mapped.has(id)) throw new Error(`${label} coverage repeats ${id}`);
    mapped.set(id, record);
  }
  return mapped;
}

function targetDigest(dimension, targets) {
  return sha256(JSON.stringify({
    coverage_schema_version: MACHINE_COVERAGE_SCHEMA_VERSION,
    dimension,
    targets: targets.map(target => ({ kind: target.kind, id: target.id })),
  }));
}

function closed(record) {
  return record?.status === "REVIEWED" || record?.status === "FINDING";
}

function findings(record) {
  return record?.status === "FINDING" && Array.isArray(record.finding_ids)
    ? record.finding_ids.filter(id => typeof id === "string" && id)
    : [];
}

export function deriveCoverageCells(report, catalogEntries) {
  if (!report?.scope || typeof report.scope !== "object") throw new Error("report scope is missing");
  const fileIds = exactUniqueIds(report.scope.assigned_file_ids, "assigned_file_ids");
  const functionIds = exactUniqueIds(report.scope.assigned_function_ids, "assigned_function_ids");
  const catalogIds = exactUniqueIds(report.scope.assigned_catalog_ids, "assigned_catalog_ids");
  const files = recordMap(report.file_coverage, "file_id", "file");
  const functions = recordMap(report.function_coverage, "function_id", "function");
  const catalog = recordMap(report.catalog_coverage, "catalog_id", "catalog");

  return DIMENSIONS.map(dimension => {
    const targets = [
      ...fileIds.map(id => ({ kind: "file", id, record: files.get(id) })),
      ...functionIds.map(id => ({ kind: "function", id, record: functions.get(id) })),
      ...catalogIds.flatMap(id => {
        const entry = catalogEntries.get(id);
        if (!entry) throw new Error(`assigned catalog ID is unknown: ${id}`);
        return entry.dimensions?.includes(dimension) ? [{ kind: "catalog", id, record: catalog.get(id) }] : [];
      }),
    ].sort((left, right) => `${left.kind}:${left.id}`.localeCompare(`${right.kind}:${right.id}`));

    const machineTargetCount = targets.length;
    const closedTargetCount = targets.filter(target => closed(target.record)).length;
    const openTargetCount = machineTargetCount - closedTargetCount;
    const findingIds = [...new Set(targets.flatMap(target => findings(target.record)))].sort();
    const status = machineTargetCount === 0
      ? "N/A"
      : openTargetCount > 0
        ? "GAP"
        : findingIds.length > 0 ? "FINDING" : "PASS";
    const digest = targetDigest(dimension, targets);
    const summary = {
      kind: "coverage-cell-summary",
      coverage_schema_version: MACHINE_COVERAGE_SCHEMA_VERSION,
      scope_digest: report.scope.scope_digest ?? report.scope_digest ?? null,
      target_digest: digest,
      machine_target_count: machineTargetCount,
      closed_target_count: closedTargetCount,
      open_target_count: openTargetCount,
      subject_counts: {
        files: targets.filter(target => target.kind === "file").length,
        functions: targets.filter(target => target.kind === "function").length,
        catalog: targets.filter(target => target.kind === "catalog").length,
      },
    };
    return {
      dimension,
      lens: report.audit_strategy,
      status,
      finding_ids: findingIds,
      evidence: [summary],
      gap_reason: status === "GAP" ? `machine-derived-open-targets:${openTargetCount}` : null,
      na_reason: status === "N/A" ? "no-machine-assigned-targets" : null,
    };
  });
}
