import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { link, lstat, mkdir, readFile, readdir, readlink, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  }
  return value;
}

export function canonicalJson(value) {
  return `${JSON.stringify(stable(value), null, 2)}\n`;
}

export function artifactSha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function hashFile(path, hash) {
  for await (const chunk of createReadStream(path)) hash.update(chunk);
}

export async function digestPath(path, { excludedPaths = [] } = {}) {
  const root = resolve(path);
  const exclusions = excludedPaths.map(item => resolve(item));
  const hash = createHash("sha256");
  async function visit(current) {
    if (current !== root && exclusions.some(excluded => current === excluded || current.startsWith(`${excluded}/`) || current.startsWith(`${excluded}\\`))) return;
    const info = await lstat(current);
    const name = relative(root, current).replaceAll("\\", "/") || ".";
    if (info.isSymbolicLink()) {
      hash.update(`L\0${name}\0${await readlink(current)}\0`);
      return;
    }
    if (info.isDirectory()) {
      hash.update(`D\0${name}\0`);
      const entries = await readdir(current);
      for (const entry of entries.sort()) await visit(join(current, entry));
      return;
    }
    if (info.isFile()) {
      hash.update(`F\0${name}\0${info.size}\0`);
      await hashFile(current, hash);
      hash.update("\0");
    }
  }
  await visit(root);
  return hash.digest("hex");
}

function normalizeSarif(sarif, scanRunId) {
  if (sarif?.version !== "2.1.0" || !Array.isArray(sarif.runs)) throw new Error("Static result is not SARIF 2.1.0");
  const runs = sarif.runs.map(run => ({
    ...run,
    tool: run.tool?.driver ? { ...run.tool, driver: { ...run.tool.driver, rules: [...(run.tool.driver.rules ?? [])].sort((left, right) => String(left.id ?? "").localeCompare(String(right.id ?? "")))} } : run.tool,
    automationDetails: { ...(run.automationDetails ?? {}), id: scanRunId },
    results: [...(run.results ?? [])].sort((left, right) => {
      const leftKey = `${left.ruleId ?? ""}\0${left.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? ""}\0${left.locations?.[0]?.physicalLocation?.region?.startLine ?? 0}`;
      const rightKey = `${right.ruleId ?? ""}\0${right.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? ""}\0${right.locations?.[0]?.physicalLocation?.region?.startLine ?? 0}`;
      return leftKey.localeCompare(rightKey);
    }),
  }));
  return { ...sarif, runs };
}

async function atomicWrite(path, bytes) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${Date.now()}.tmp`);
  try {
    await writeFile(temporary, bytes, "utf8");
    try {
      await rename(temporary, path);
    } catch (error) {
      if (!["EEXIST", "EPERM"].includes(error.code)) throw error;
      const backup = `${path}.${process.pid}.${Date.now()}.bak`;
      await rename(path, backup);
      try {
        await rename(temporary, path);
        await rm(backup, { force: true });
      } catch (replacementError) {
        await rename(backup, path);
        throw replacementError;
      }
    }
  } finally {
    await rm(temporary, { force: true });
  }
}

async function createImmutable(path, bytes) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${Date.now()}.tmp`);
  try {
    await writeFile(temporary, bytes, "utf8");
    try {
      await link(temporary, path);
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      if (await readFile(path, "utf8") !== bytes) throw new Error(`Immutable static artifact conflict: ${path}`);
    }
  } finally {
    await rm(temporary, { force: true });
  }
}

export async function writeStaticRun({ reportsRoot, auditId, identity, sarif, summary }) {
  if (!/^[a-z0-9][a-z0-9._-]{2,127}$/i.test(auditId)) throw new Error(`Invalid audit_id: ${auditId}`);
  const scanRunId = artifactSha256(canonicalJson(identity));
  const directory = join(resolve(reportsRoot), "static-analysis", auditId, scanRunId);
  const normalizedSarif = normalizeSarif(sarif, scanRunId);
  const sarifBytes = canonicalJson(normalizedSarif);
  const normalizedSummary = {
    schema_version: "static-scan-summary.v1",
    scan_run_id: scanRunId,
    audit_id: auditId,
    status: summary.status,
    engine: summary.engine,
    engine_version: summary.engine_version,
    findings: summary.findings,
    errors: summary.errors,
    target_digest: identity.target_digest,
    rule_pack_digest: identity.rule_pack_digest,
  };
  const summaryBytes = canonicalJson(normalizedSummary);
  const manifestBase = {
    schema_version: "static-scan-run.v1",
    scan_run_id: scanRunId,
    audit_id: auditId,
    status: summary.status,
    capability: identity.capability,
    engine: { id: summary.engine, version: summary.engine_version },
    inputs: identity,
    accounting: {
      requested_rules: summary.requested_rules ?? [],
      executed_rules: summary.executed_rules ?? [],
      skipped_rules: summary.skipped_rules ?? [],
      target_files: summary.target_files ?? null,
      parsed_files: summary.parsed_files ?? null,
      skipped_files: summary.skipped_files ?? null,
      findings: summary.findings,
      errors: summary.errors,
    },
    artifacts: {
      sarif: { path: "result.sarif", sha256: artifactSha256(sarifBytes) },
      summary: { path: "summary.json", sha256: artifactSha256(summaryBytes) },
    },
  };
  const manifestDigest = artifactSha256(canonicalJson(manifestBase));
  const manifestBytes = canonicalJson({ ...manifestBase, manifest_digest: manifestDigest });
  for (const [name, bytes] of [["result.sarif", sarifBytes], ["summary.json", summaryBytes], ["manifest.json", manifestBytes]]) {
    await createImmutable(join(directory, name), bytes);
  }
  return {
    scan_run_id: scanRunId,
    directory,
    manifest_path: join(directory, "manifest.json"),
    summary_path: join(directory, "summary.json"),
    sarif_path: join(directory, "result.sarif"),
    manifest_digest: manifestDigest,
  };
}

export async function verifyStaticRun(directory) {
  const manifest = JSON.parse(await readFile(join(directory, "manifest.json"), "utf8"));
  const suppliedDigest = manifest.manifest_digest;
  const { manifest_digest: _ignored, ...base } = manifest;
  const issues = [];
  if (artifactSha256(canonicalJson(base)) !== suppliedDigest) issues.push("manifest_digest mismatch");
  for (const artifact of Object.values(manifest.artifacts ?? {})) {
    try {
      const bytes = await readFile(join(directory, artifact.path), "utf8");
      if (artifactSha256(bytes) !== artifact.sha256) issues.push(`${artifact.path} digest mismatch`);
    } catch (error) {
      issues.push(`${artifact.path}: ${error.code ?? error.message}`);
    }
  }
  return { complete: issues.length === 0, scan_run_id: manifest.scan_run_id, issues, manifest };
}

export async function aggregateStaticRuns({ reportsRoot, auditId, outputPath }) {
  if (!/^[a-z0-9][a-z0-9._-]{2,127}$/i.test(auditId)) throw new Error(`Invalid audit_id: ${auditId}`);
  const root = join(resolve(reportsRoot), "static-analysis", auditId);
  const entries = (await readdir(root, { withFileTypes: true })).filter(entry => entry.isDirectory()).map(entry => entry.name).sort();
  const runs = [];
  for (const entry of entries) {
    const directory = join(root, entry);
    const verification = await verifyStaticRun(directory);
    if (!verification.complete) throw new Error(`Invalid static run ${entry}: ${verification.issues.join("; ")}`);
    const sarif = JSON.parse(await readFile(join(directory, "result.sarif"), "utf8"));
    runs.push(...sarif.runs);
  }
  const aggregate = { version: "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", runs };
  const destination = resolve(outputPath);
  const allowed = resolve(reportsRoot, "sarif");
  const rel = relative(allowed, destination);
  if (rel === ".." || rel.startsWith("../") || rel.startsWith("..\\")) throw new Error("Aggregate SARIF must stay under reports/sarif/");
  await atomicWrite(destination, canonicalJson(aggregate));
  return { complete: true, audit_id: auditId, scan_runs: entries.length, sarif_runs: runs.length, output_path: destination, sha256: artifactSha256(canonicalJson(aggregate)) };
}
