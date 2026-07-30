#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { objectDigest } from "../skills/common-subagent/audit-coverage-accounting/scripts/coverage-v2-common.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPOSITORY = resolve(HERE, "../..");
const SCRIPT = resolve(REPOSITORY, ".opencode/skills/common-subagent/audit-coverage-accounting/scripts/reseed-semantic-manifests.mjs");
const SOURCE_AUDIT = "source-audit";
const TARGET_AUDIT = "target-audit";
const SOURCE_SCOPE_DIGEST = "a".repeat(64);
const TARGET_SCOPE_DIGEST = "b".repeat(64);

function semanticDigest(value) {
  const copy = structuredClone(value);
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

function scope(auditId, scopeDigest, sourceDigest, includeAtlas = false) {
  const value = {
    schema_version: 1,
    audit_id: auditId,
    scope_digest: scopeDigest,
    files: [{ file_id: "file:source", path: "src/App.java", sha256: sourceDigest }],
    complete: true,
  };
  if (includeAtlas) value.files.push({ file_id: "file:atlas", path: ".atlas/atlas.db", sha256: "c".repeat(64) });
  value.manifest_digest = objectDigest(value);
  return value;
}

function sourceManifests() {
  const threat = {
    schema_version: 1,
    audit_id: SOURCE_AUDIT,
    scope_digest: SOURCE_SCOPE_DIGEST,
    entry_points: [],
    threats: [],
  };
  threat.manifest_digest = semanticDigest(threat);
  const focus = {
    schema_version: 1,
    audit_id: SOURCE_AUDIT,
    scope_digest: SOURCE_SCOPE_DIGEST,
    threat_model_digest: threat.manifest_digest,
    required_lenses: ["sink-driven", "control-driven", "config-driven"],
    focus_areas: [{
      focus_area_id: "FA-001",
      context_file_ids: ["file:atlas"],
      assignments: [{ file_ids: ["file:source", "file:atlas"] }],
    }],
  };
  focus.manifest_digest = semanticDigest(focus);
  return { threat, focus };
}

function run(args, expectedStatus = 0) {
  const result = spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8" });
  assert.equal(result.status, expectedStatus, `reseed script returned ${result.status}: ${result.stderr}`);
}

async function writeJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "opencode-semantic-reseed-"));
  try {
    const sourceScopePath = join(work, "source-scope.json");
    const targetScopePath = join(work, "target-scope.json");
    const threatPath = join(work, "source-threat.json");
    const focusPath = join(work, "source-focus.json");
    const targetThreatPath = join(work, "target-threat.json");
    const targetFocusPath = join(work, "target-focus.json");
    const { threat, focus } = sourceManifests();
    await Promise.all([
      writeJson(sourceScopePath, scope(SOURCE_AUDIT, SOURCE_SCOPE_DIGEST, "d".repeat(64), true)),
      writeJson(targetScopePath, scope(TARGET_AUDIT, TARGET_SCOPE_DIGEST, "d".repeat(64))),
      writeJson(threatPath, threat),
      writeJson(focusPath, focus),
    ]);
    const baseArgs = [
      "--audit-id", TARGET_AUDIT,
      "--scope", targetScopePath,
      "--source-scope", sourceScopePath,
      "--source-threat-model", threatPath,
      "--source-focus-areas", focusPath,
      "--threat-output", targetThreatPath,
      "--focus-output", targetFocusPath,
    ];
    run(baseArgs);
    const [targetThreat, targetFocus] = await Promise.all([readFile(targetThreatPath, "utf8").then(JSON.parse), readFile(targetFocusPath, "utf8").then(JSON.parse)]);
    assert.equal(targetThreat.audit_id, TARGET_AUDIT);
    assert.equal(targetThreat.scope_digest, TARGET_SCOPE_DIGEST);
    assert.equal(targetThreat.carry_forward.revalidation_required, true);
    assert.equal(targetFocus.threat_model_digest, targetThreat.manifest_digest);
    assert.equal(targetFocus.carry_forward.revalidation_required, true);
    assert.deepEqual(targetFocus.carry_forward.pruned_regenerable_cache_file_ids, ["file:atlas"]);
    assert.deepEqual(targetFocus.focus_areas[0].context_file_ids, []);
    assert.deepEqual(targetFocus.focus_areas[0].assignments[0].file_ids, ["file:source"]);

    await writeJson(targetScopePath, scope(TARGET_AUDIT, TARGET_SCOPE_DIGEST, "e".repeat(64)));
    run(baseArgs, 1);
    process.stdout.write(`${JSON.stringify({ complete: true, semantic_reseed: "source-equivalence-required", cases: 2 })}\n`);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
