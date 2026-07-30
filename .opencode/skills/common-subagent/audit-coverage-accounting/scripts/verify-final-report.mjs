#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { renderFinalReport, validateFinalReportModel } from "./final-report-model-core.mjs";

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== "--model" || args[2] !== "--markdown") throw new Error("Usage: verify-final-report.mjs --model <model.json> --markdown <report.md>");
  const [model, markdown] = await Promise.all([
    readFile(resolve(args[1]), "utf8").then(JSON.parse),
    readFile(resolve(args[3]), "utf8"),
  ]);
  const errors = validateFinalReportModel(model);
  if (/\bCONFIRMED\b/.test(markdown)) errors.push("final-report-forbidden-confirmed-label");
  if (markdown.includes("security-attack-chain-hunter.")) errors.push("final-report-direct-raw-chain-reference");
  if (markdown !== renderFinalReport(model)) errors.push("final-report-not-deterministic-render");
  if (errors.length > 0) throw new Error(`Final report is invalid:\n- ${errors.join("\n- ")}`);
  process.stdout.write(`${JSON.stringify({ valid: true, audit_id: model.audit_id, report_kind: model.report_kind, model_digest: model.manifest_digest })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
