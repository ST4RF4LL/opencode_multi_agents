#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, writeFile, realpath, lstat } from "node:fs/promises";
import { resolve, relative, isAbsolute, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { deriveCoverageCells, LENSES, DIMENSIONS } from "./coverage-cell-accounting.mjs";

const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const precedence = ["N/A", "PASS", "FINDING", "GAP"];

// This is a projection of accepted reports, never a substitute for the full
// frozen-plan/entity/semantic coverage verifiers or the TODO completion gate.
export async function buildCorrelationCoverage({ manifest, scope, catalog, reportsRoot }) {
  if (typeof scope.audit_id !== "string" || !scope.audit_id || !/^[a-f0-9]{64}$/.test(scope.scope_digest ?? "")
    || manifest.audit_id !== scope.audit_id || manifest.scope_digest !== scope.scope_digest
    || !Number.isInteger(manifest.round) || manifest.round < 1 || !Array.isArray(manifest.reports)) throw new Error("关联输入的审计、轮次或范围绑定无效。");
  const root = await realpath(resolve(reportsRoot));
  const result = { schema_version: 1, audit_id: manifest.audit_id, round: manifest.round,
    scope_digest: scope.scope_digest, input_digest: sha(JSON.stringify({ manifest, scope, catalog })),
    consumed_artifacts: [], rejected_artifacts: [], coverage_cells: [], dimension_summary: [],
    file_coverage_records: [], function_coverage_records: [], catalog_coverage_records: [], residual_gaps: [] };
  const seen = new Set();
  for (const binding of manifest.reports) {
    try {
      if (typeof binding.path !== "string" || isAbsolute(binding.path) || !/^[a-f0-9]{64}$/.test(binding.sha256 ?? "")) throw new Error("报告路径或摘要无效");
      const path = resolve(root, binding.path), rel = relative(root, path);
      if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error("报告路径越界");
      const info = await lstat(path), actual = relative(root, await realpath(path));
      if (!info.isFile() || info.isSymbolicLink() || actual === ".." || actual.startsWith(`..${sep}`) || isAbsolute(actual)) throw new Error("报告必须是根目录内的普通文件");
      const bytes = await readFile(path);
      if (sha(bytes) !== binding.sha256) throw new Error("报告摘要不匹配");
      const report = JSON.parse(bytes);
      if (report.audit_id !== manifest.audit_id || report.round !== manifest.round
        || (report.scope?.scope_digest ?? report.scope_digest) !== scope.scope_digest
        || report.discovery_track !== "coverage" || !LENSES.includes(report.audit_strategy)
        || !report.focus_area_id || !report.agent_session_id || !report.agent_name || !report.language || !report.scope?.focus_assignment_id) throw new Error("报告身份或范围不匹配");
      const identity = JSON.stringify([report.agent_session_id, report.focus_area_id, report.scope.focus_assignment_id, report.audit_strategy]);
      if (seen.has(identity)) throw new Error("重复报告身份");
      const cells = deriveCoverageCells(report, new Map((catalog.entries ?? []).map(entry => [entry.id, entry])));
      if (!isDeepStrictEqual(cells, report.coverage_cells)) throw new Error("报告尚未归一化或覆盖统计被修改");
      for (const kind of ["file", "function", "catalog"]) {
        const rows = report[`${kind}_coverage`], assigned = report.scope[`assigned_${kind}_ids`];
        if (rows.length !== assigned.length || rows.some(row => !assigned.includes(row[`${kind}_id`]) || typeof row.domain !== "string" || !row.domain || !["REVIEWED", "FINDING", "GAP"].includes(row.status))) throw new Error("实体记录超出分配范围或状态无效");
      }
      const provenance = { source_report: binding.path, source_sha256: binding.sha256,
        agent_session_id: report.agent_session_id, owner_agent: report.agent_name,
        focus_area_id: report.focus_area_id, assignment_id: report.scope.focus_assignment_id,
        language: report.language,
        domain: report.agent_name === "ai-security-auditor" ? "ai" : "base",
        lens: report.audit_strategy, round: report.round };
      seen.add(identity);
      result.consumed_artifacts.push(binding);
      result.coverage_cells.push(...cells.map(cell => ({ ...provenance, ...cell })));
      for (const kind of ["file", "function", "catalog"]) {
        result[`${kind}_coverage_records`].push(...report[`${kind}_coverage`].map(record => ({ ...record, ...provenance, domain: record.domain })));
      }
    } catch (error) {
      result.rejected_artifacts.push({ ...binding, reason: error.message });
      result.residual_gaps.push({ kind: "schema", source_report: binding?.path ?? null, reason: error.message });
    }
  }
  const groups = new Map();
  for (const cell of result.coverage_cells) {
    const key = JSON.stringify([cell.focus_area_id, cell.assignment_id, cell.owner_agent]);
    if (!groups.has(key)) groups.set(key, new Set());
    groups.get(key).add(cell.lens);
  }
  const openAssignments = new Map();
  for (const cell of result.coverage_cells.filter(cell => cell.status === "GAP")) {
    const key = JSON.stringify([cell.source_report, cell.assignment_id, cell.lens]);
    if (!openAssignments.has(key)) openAssignments.set(key, { kind: "open-targets", source_report: cell.source_report, assignment_id: cell.assignment_id, lens: cell.lens, dimensions: [] });
    openAssignments.get(key).dimensions.push(cell.dimension);
  }
  result.residual_gaps.push(...openAssignments.values());
  for (const [assignment, lenses] of groups) {
    const missing = LENSES.filter(lens => !lenses.has(lens));
    if (missing.length) result.residual_gaps.push({ kind: "missing-lens", assignment, missing });
  }
  if (!result.consumed_artifacts.length) result.residual_gaps.push({ kind: "empty-coverage", reason: "没有可消费的覆盖报告，不能推断完整性。" });
  for (const dimension of DIMENSIONS) {
    const cells = result.coverage_cells.filter(cell => cell.dimension === dimension);
    const missingLens = LENSES.some(lens => !cells.some(cell => cell.lens === lens));
    const status = result.residual_gaps.some(gap => gap.kind !== "open-targets") || missingLens ? "GAP"
      : precedence[Math.max(...cells.map(cell => precedence.indexOf(cell.status)))];
    result.dimension_summary.push({ dimension, status, projection_only: true });
  }
  result.manifest_digest = sha(JSON.stringify(result));
  return result;
}

async function main() {
  const args = {};
  for (let i = 2; i < process.argv.length; i += 2) {
    if (!process.argv[i].startsWith("--") || !process.argv[i + 1]) throw new Error("参数必须为 --名称 值");
    args[process.argv[i].slice(2)] = process.argv[i + 1];
  }
  for (const key of ["manifest", "scope", "catalog", "reports-root", "output"]) if (!args[key]) throw new Error(`缺少 --${key}`);
  const output = resolve(args.output);
  if ([args.manifest, args.scope, args.catalog, args.correlation].filter(Boolean).some(path => resolve(path) === output)) throw new Error("输出路径不能覆盖输入制品。");
  const [manifest, scope, catalog] = await Promise.all([args.manifest, args.scope, args.catalog].map(path => readFile(resolve(path), "utf8").then(JSON.parse)));
  if (manifest.reports.some(binding => typeof binding?.path === "string" && [output, args.correlation && resolve(args.correlation)].includes(resolve(args["reports-root"], binding.path)))) throw new Error("输出路径不能覆盖源码报告。");
  const result = await buildCorrelationCoverage({ manifest, scope, catalog, reportsRoot: args["reports-root"] });
  await writeFile(resolve(args.output), `${JSON.stringify(result, null, 2)}\n`);
  if (args.correlation) {
    const path = resolve(args.correlation), semantic = JSON.parse(await readFile(path, "utf8"));
    if (semantic.audit_id !== result.audit_id || semantic.round !== result.round) throw new Error("语义关联报告身份不匹配");
    for (const field of ["coverage_cells", "dimension_summary", "file_coverage_records", "function_coverage_records", "catalog_coverage_records"]) semantic[field] = result[field];
    semantic.machine_coverage = { path: resolve(args.output), sha256: sha(await readFile(resolve(args.output))), input_digest: result.input_digest };
    // Preserve semantic gaps; replace only this builder's previous diagnostic rows.
    semantic.residual_gaps = [...(semantic.residual_gaps ?? []).filter(row => row?.producer !== "correlation-coverage"), ...result.residual_gaps.map(row => ({ ...row, producer: "correlation-coverage" }))];
    semantic.coverage_rejected_artifacts = result.rejected_artifacts;
    await writeFile(path, `${JSON.stringify(semantic, null, 2)}\n`);
  }
  process.stdout.write(`${JSON.stringify({ output: args.output, accepted: result.consumed_artifacts.length, rejected: result.rejected_artifacts.length })}\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main().catch(error => { process.stderr.write(`${error.stack ?? error}\n`); process.exitCode = 1; });
