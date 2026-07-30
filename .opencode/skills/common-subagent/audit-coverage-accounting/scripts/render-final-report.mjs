#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { renderFinalReport, validateFinalReportModel } from "./final-report-model-core.mjs";

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== "--model" || args[2] !== "--output") throw new Error("Usage: render-final-report.mjs --model <model.json> --output <report.md>");
  const model = JSON.parse(await readFile(resolve(args[1]), "utf8"));
  const errors = validateFinalReportModel(model);
  if (errors.length > 0) throw new Error(`Final report model is invalid:\n- ${errors.join("\n- ")}`);
  const output = resolve(args[3]);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, renderFinalReport(model), "utf8");
  process.stdout.write(`${JSON.stringify({ output, model_digest: model.manifest_digest })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
