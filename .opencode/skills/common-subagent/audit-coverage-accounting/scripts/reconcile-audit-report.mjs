#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { deriveCoverageCells } from "./coverage-cell-accounting.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["report", "scope", "catalog"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const reportPath = resolve(args.report);
  const outputPath = resolve(args.output ?? args.report);
  const [report, scope, catalog] = await Promise.all([
    readFile(reportPath, "utf8").then(JSON.parse),
    readFile(resolve(args.scope), "utf8").then(JSON.parse),
    readFile(resolve(args.catalog), "utf8").then(JSON.parse),
  ]);
  if (report.audit_id !== scope.audit_id || (report.scope?.scope_digest ?? report.scope_digest) !== scope.scope_digest) {
    throw new Error("Report audit/scope binding does not match the frozen scope manifest");
  }
  const catalogEntries = new Map((catalog.entries ?? []).map(entry => [entry.id, entry]));
  report.coverage_cells = deriveCoverageCells(report, catalogEntries);
  await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: outputPath, audit_id: report.audit_id, lens: report.audit_strategy, cells: report.coverage_cells.map(cell => ({ dimension: cell.dimension, status: cell.status, targets: cell.evidence[0].machine_target_count, closed: cell.evidence[0].closed_target_count })) })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
