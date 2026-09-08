import { EventEmitter } from "node:events";
import { streamAuditEvents } from "../web/dynamic-validation-observatory/server.mjs";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, appendFile, readFile, stat, rename, rm, utimes } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { EventLogReader } from "../web/dynamic-validation-observatory/event-log-reader.mjs";
import { reconcileReport } from "../skills/common-subagent/audit-coverage-accounting/scripts/reconcile-audit-report.mjs";
import { buildCorrelationCoverage } from "../skills/common-subagent/audit-coverage-accounting/scripts/build-correlation-coverage.mjs";
import { deriveCoverageCells, LENSES } from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-cell-accounting.mjs";

const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const root = await mkdtemp(join(tmpdir(), "audit-redundancy-"));
try {
  const log = join(root, "events.jsonl"), reader = new EventLogReader();
  const event = (sequence, label = "中文事件") => ({ event_id: `event-${sequence}`, sequence, message: label });
  const line = sequence => `${JSON.stringify(event(sequence))}\n`;
  assert.deepEqual(await reader.eventsSince(log), []);
  await writeFile(log, line(1) + line(2));
  assert.deepEqual(await reader.eventsSince(log, 1), [event(2)]);
  await appendFile(log, line(3));
  assert.deepEqual(await reader.eventsSince(log, 2), [event(3)]);
  assert.deepEqual(await reader.eventsSince(log, 0, "event-2"), [event(3)]);
  assert.deepEqual(await reader.eventsSince(log, 2, "unknown"), [event(3)]);
  assert.deepEqual(await Promise.all([reader.eventsSince(log, 2), reader.eventsSince(log, 3)]), [[event(3)], []]);
  // A partial UTF-8 record remains pending until its newline is present.
  const fourth = Buffer.from(line(4));
  await appendFile(log, fourth.subarray(0, fourth.length - 4));
  assert.deepEqual(await reader.eventsSince(log, 3), []);
  await appendFile(log, fourth.subarray(fourth.length - 4));
  assert.deepEqual(await reader.eventsSince(log, 3), [event(4)]);
  await writeFile(log, line(1));
  assert.deepEqual(await reader.eventsSince(log), [event(1)], "截断后重建索引");
  const replacement = join(root, "replacement.jsonl");
  await writeFile(replacement, line(1) + line(2));
  await rm(log); await rename(replacement, log);
  assert.deepEqual(await reader.eventsSince(log, 1), [event(2)], "替换文件后重建索引");
  await appendFile(log, '{broken}\n');
  await assert.rejects(reader.eventsSince(log), /JSON|Unexpected|property/i);
  await writeFile(log, line(1));
  assert.deepEqual(await reader.eventsSince(log), [event(1)], "解析失败后的索引可恢复");

  // Subscribe before replay: an event emitted while reading must arrive once.
  const request = new EventEmitter();
  request.url = "/events?after=1"; request.headers = { "last-event-id": "event-1" };
  const chunks = [], subscribers = new Set();
  const response = { destroyed: false, writeHead() {}, write(value) { chunks.push(value); } };
  const mockRunner = {
    getAudit() { return { id: "audit-fixture" }; },
    subscribe(id, callback) { subscribers.add(callback); return () => subscribers.delete(callback); },
    async eventsSince(id, sequence, lastId) {
      assert.equal(sequence, 1); assert.equal(lastId, "event-1");
      for (const callback of subscribers) callback(event(3));
      return [event(2), event(3)];
    },
  };
  await streamAuditEvents(request, response, mockRunner, "audit-fixture");
  for (const callback of subscribers) callback(event(4));
  request.emit("close");
  assert.equal(subscribers.size, 0);
  assert.deepEqual(chunks.map(chunk => JSON.parse(chunk.split("data: ")[1]).sequence), [2, 3, 4]);

  const scope = { audit_id: "audit-fixture", scope_digest: "a".repeat(64) }, catalog = { entries: [] };
  const scopePath = join(root, "scope.json"), catalogPath = join(root, "catalog.json");
  await writeFile(scopePath, JSON.stringify(scope)); await writeFile(catalogPath, JSON.stringify(catalog));
  const makeReport = lens => ({ audit_id: scope.audit_id, round: 1, agent_name: "java-source-auditor", agent_session_id: "session-1",
    focus_area_id: "focus-1", language: "java", discovery_track: "coverage", audit_strategy: lens,
    scope: { scope_digest: scope.scope_digest, focus_assignment_id: "assignment-1", assigned_file_ids: ["f1"], assigned_function_ids: [], assigned_catalog_ids: [] },
    file_coverage: [{ file_id: "f1", domain: "base", status: lens === "control-driven" ? "GAP" : "REVIEWED", evidence: [{ path: "A.java", note: "证据原文" }] }],
    function_coverage: [], catalog_coverage: [], findings: [] });
  const bindings = [];
  for (const lens of LENSES) {
    const report = makeReport(lens), path = join(root, `${lens}.json`);
    await writeFile(path, JSON.stringify(report));
    await reconcileReport({ report: path, scope: scopePath, catalog: catalogPath });
    const bytes = await readFile(path);
    await utimes(path, new Date("2001-01-01"), new Date("2001-01-01"));
    const mtime = (await stat(path)).mtimeMs;
    assert.equal((await reconcileReport({ report: path, scope: scopePath, catalog: catalogPath })).unchanged, true);
    await reconcileReport({ report: path, scope: scopePath, catalog: catalogPath, mode: "verify" });
    assert.equal((await stat(path)).mtimeMs, mtime, "重复归一化与 verify 都不得写文件");
    assert.deepEqual(await readFile(path), bytes);
    bindings.push({ path: `${lens}.json`, sha256: hash(bytes) });
  }
  const manifest = { audit_id: scope.audit_id, scope_digest: scope.scope_digest, round: 1, reports: bindings };
  const result = await buildCorrelationCoverage({ manifest, scope, catalog, reportsRoot: root });
  assert.equal(result.rejected_artifacts.length, 0);
  assert.equal(result.file_coverage_records.length, 3);
  assert.ok(result.dimension_summary.every(cell => cell.status === "GAP"), "一视角 GAP 不得被其他 PASS 隐藏");
  assert.deepEqual(result.file_coverage_records[0].evidence, makeReport(LENSES[0]).file_coverage[0].evidence);
  const missing = await buildCorrelationCoverage({ manifest: { ...manifest, reports: bindings.slice(1) }, scope, catalog, reportsRoot: root });
  assert.ok(missing.residual_gaps.some(gap => gap.kind === "missing-lens"));
  const duplicate = await buildCorrelationCoverage({ manifest: { ...manifest, reports: [...bindings, bindings[0]] }, scope, catalog, reportsRoot: root });
  assert.equal(duplicate.rejected_artifacts.length, 1);
  const manifestPath = join(root, "bindings.json"), projectionPath = join(root, "projection.json"), correlationPath = join(root, "correlation.json");
  await writeFile(manifestPath, JSON.stringify(manifest));
  const semantic = { audit_id: scope.audit_id, round: 1, canonical_findings: [{ canonical_id: "candidate-1" }], residual_gaps: [{ kind: "semantic", reason: "待核实" }] };
  await writeFile(correlationPath, JSON.stringify(semantic));
  const script = fileURLToPath(new URL("../skills/common-subagent/audit-coverage-accounting/scripts/build-correlation-coverage.mjs", import.meta.url));
  const args = [script, "--manifest", manifestPath, "--scope", scopePath, "--catalog", catalogPath, "--reports-root", root, "--output", projectionPath, "--correlation", correlationPath];
  for (let attempt = 0; attempt < 2; attempt++) {
    const child = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.equal(child.status, 0, child.stderr);
  }
  const merged = JSON.parse(await readFile(correlationPath));
  assert.deepEqual(merged.canonical_findings, semantic.canonical_findings);
  assert.deepEqual(merged.residual_gaps.filter(gap => gap.producer !== "correlation-coverage"), semantic.residual_gaps);
  assert.equal(merged.residual_gaps.filter(gap => gap.kind === "open-targets").length, 1, "反复合并不重复添加机器缺口");
  assert.equal(merged.file_coverage_records.length, 3);
  // A changed sealed source fails verification and cannot be silently repaired.
  const altered = makeReport(LENSES[0]);
  altered.coverage_cells = deriveCoverageCells(altered, new Map());
  altered.file_coverage[0].status = "GAP";
  const alteredPath = join(root, bindings[0].path);
  await writeFile(alteredPath, JSON.stringify(altered));
  const alteredBytes = await readFile(alteredPath);
  await assert.rejects(reconcileReport({ report: alteredPath, scope: scopePath, catalog: catalogPath, mode: "verify" }), /不一致/);
  assert.deepEqual(await readFile(alteredPath), alteredBytes);
  const tampered = await buildCorrelationCoverage({ manifest, scope, catalog, reportsRoot: root });
  assert.equal(tampered.rejected_artifacts.length, 1);
  assert.match(tampered.rejected_artifacts[0].reason, /摘要/);
  const foreign = await buildCorrelationCoverage({ manifest: { ...manifest, reports: [{ path: "../outside.json", sha256: "a".repeat(64) }] }, scope, catalog, reportsRoot: root });
  assert.equal(foreign.rejected_artifacts.length, 1);
  process.stdout.write("冗余优化回归用例通过。\n");
} finally { await rm(root, { recursive: true, force: true }); }
