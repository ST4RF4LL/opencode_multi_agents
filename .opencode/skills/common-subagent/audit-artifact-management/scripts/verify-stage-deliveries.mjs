#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAuditStageDeliveries } from "./stage-delivery-materialization.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = resolve(HERE, "../contracts");

function argument(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : null;
}

try {
  const auditId = argument("audit-id");
  const reportsRoot = resolve(argument("reports-root") ?? process.env.AUDIT_REPORTS_ROOT ?? "reports");
  if (!auditId) throw new Error("缺少 --audit-id。");
  const [registry, stageAgentRegistry] = await Promise.all([
    readFile(join(CONTRACTS, "workbench-stage-deliveries.json"), "utf8").then(JSON.parse),
    readFile(join(CONTRACTS, "stage-agent-contracts.json"), "utf8").then(JSON.parse),
  ]);
  const result = await verifyAuditStageDeliveries({ reportsRoot, auditId, registry, stageAgentRegistry });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.complete) process.exitCode = 1;
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 2;
}
