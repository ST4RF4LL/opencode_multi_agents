#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { AI_COVERAGE_POLICY, buildAiRouting } from "./ai-coverage-routing.mjs";
import { objectDigest } from "./coverage-v2-common.mjs";

// Recon-only: enrich scope before downstream parser/Focus snapshots are sealed.
const args = Object.fromEntries(Array.from({ length: process.argv.slice(2).length / 2 }, (_, index) => [process.argv[index * 2 + 2]?.replace(/^--/, ""), process.argv[index * 2 + 3]]));
try {
  if (!args.scope || !args.decisions) throw new Error("需要 --scope 和 --decisions。");
  const path = resolve(args.scope);
  const scope = JSON.parse(await readFile(path, "utf8"));
  if (scope.manifest_digest !== objectDigest(scope)) throw new Error("冻结范围摘要无效。");
  const input = JSON.parse(await readFile(resolve(args.decisions), "utf8"));
  if (input.audit_id !== scope.audit_id || input.scope_digest !== scope.scope_digest) throw new Error("AI 筛查输入与审计范围不匹配。");
  scope.ai_routing = buildAiRouting(scope, input.decisions);
  scope.policy.ai_coverage = AI_COVERAGE_POLICY;
  scope.manifest_digest = objectDigest(scope);
  await writeFile(path, JSON.stringify(scope, null, 2) + "\n");
  process.stdout.write(JSON.stringify({ complete: true, required_files: scope.ai_routing.required_file_ids.length, excluded_files: scope.ai_routing.excluded_file_ids.length, unknown_files: scope.ai_routing.unknown_file_ids.length }) + "\n");
} catch (error) { process.stderr.write(error.message + "\n"); process.exitCode = 1; }
