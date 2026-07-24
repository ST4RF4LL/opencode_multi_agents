import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const ENGINE_NAMES = new Set(["auto", "semgrep", "opengrep"]);

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isInside(root, path) {
  const rel = relative(root, path);
  return rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`));
}

export async function resolveWorkspacePath(workspaceRoot, inputPath, { mustExist = true } = {}) {
  const root = await realpath(resolve(workspaceRoot));
  const candidate = resolve(root, inputPath);
  if (!isInside(root, candidate)) throw new Error(`Path escapes workspace: ${inputPath}`);
  if (mustExist) {
    const actual = await realpath(candidate);
    if (!isInside(root, actual)) throw new Error(`Symlink target escapes workspace: ${inputPath}`);
    return actual;
  }
  let ancestor = candidate;
  const missingSegments = [];
  while (true) {
    try {
      const actualAncestor = await realpath(ancestor);
      const actual = resolve(actualAncestor, ...missingSegments);
      if (!isInside(root, actual)) throw new Error(`Symlink target escapes workspace: ${inputPath}`);
      return actual;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      const parent = dirname(ancestor);
      if (parent === ancestor) throw error;
      missingSegments.unshift(basename(ancestor));
      ancestor = parent;
    }
  }
}

function runProcess(command, args, { cwd, timeoutMs, env = {} }) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: {
        ...process.env,
        SEMGREP_SEND_METRICS: "off",
        SEMGREP_ENABLE_VERSION_CHECK: "0",
        ...env,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 2_000).unref();
    }, timeoutMs);
    child.stdout.on("data", chunk => { stdout += chunk.toString(); });
    child.stderr.on("data", chunk => { stderr += chunk.toString(); });
    child.on("error", error => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", code => {
      clearTimeout(timer);
      if (timedOut) {
        reject(new Error(`Static-analysis process timed out after ${timeoutMs} ms`));
        return;
      }
      resolvePromise({ code, stdout, stderr });
    });
  });
}

function engineCommands(engine, environment = process.env) {
  if (!ENGINE_NAMES.has(engine)) throw new Error(`Unsupported engine: ${engine}`);
  const semgrep = environment.SEMGREP_BIN || "semgrep";
  const opengrep = environment.OPENGREP_BIN || "opengrep";
  if (engine === "semgrep") return [{ engine: "semgrep", command: semgrep }];
  if (engine === "opengrep") return [{ engine: "opengrep", command: opengrep }];
  const preferred = environment.SEMGREP_ENGINE || "auto";
  if (!ENGINE_NAMES.has(preferred)) throw new Error(`Unsupported SEMGREP_ENGINE: ${preferred}`);
  if (preferred === "semgrep") return [{ engine: "semgrep", command: semgrep }, { engine: "opengrep", command: opengrep }];
  return [{ engine: "opengrep", command: opengrep }, { engine: "semgrep", command: semgrep }];
}

export async function probeEngines({ workspaceRoot, environment = process.env }) {
  const probes = [];
  for (const candidate of engineCommands("auto", environment)) {
    try {
      const result = await runProcess(candidate.command, ["--version"], {
        cwd: workspaceRoot,
        timeoutMs: 10_000,
        env: environment,
      });
      probes.push({
        ...candidate,
        available: result.code === 0,
        version: result.code === 0 ? result.stdout.trim() || result.stderr.trim() : null,
        error: result.code === 0 ? null : `exit-${result.code}: ${result.stderr.trim()}`,
      });
    } catch (error) {
      probes.push({ ...candidate, available: false, version: null, error: error.message });
    }
  }
  return probes;
}

export async function selectEngine({ workspaceRoot, engine = "auto", environment = process.env }) {
  const failures = [];
  for (const candidate of engineCommands(engine, environment)) {
    try {
      const result = await runProcess(candidate.command, ["--version"], {
        cwd: workspaceRoot,
        timeoutMs: 10_000,
        env: environment,
      });
      if (result.code === 0) {
        return {
          ...candidate,
          version: result.stdout.trim() || result.stderr.trim() || "unknown",
        };
      }
      failures.push(`${candidate.engine}: exit ${result.code} ${result.stderr.trim()}`);
    } catch (error) {
      failures.push(`${candidate.engine}: ${error.message}`);
    }
  }
  throw new Error(`No usable Semgrep/OpenGrep binary found (${failures.join("; ")})`);
}

function severityLevel(value) {
  const severity = String(value ?? "").toUpperCase();
  if (["ERROR", "CRITICAL", "HIGH"].includes(severity)) return "error";
  if (["WARNING", "WARN", "MEDIUM"].includes(severity)) return "warning";
  return "note";
}

export function semgrepJsonToSarif(payload, { engine, version, commandLine, workspaceRoot }) {
  const rules = new Map();
  const results = [];
  for (const finding of payload.results ?? []) {
    const ruleId = finding.check_id ?? "semgrep/unknown";
    const message = finding.extra?.message ?? finding.message ?? ruleId;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: ruleId,
        shortDescription: { text: String(message).slice(0, 200) },
        properties: {
          severity: finding.extra?.severity ?? null,
          metadata: finding.extra?.metadata ?? {},
        },
      });
    }
    const start = finding.start ?? {};
    const end = finding.end ?? {};
    const rawFindingPath = finding.path ?? "unknown";
    const normalizedRoot = workspaceRoot ? resolve(workspaceRoot) : null;
    const normalizedFindingPath = isAbsolute(String(rawFindingPath))
      && normalizedRoot
      && isInside(normalizedRoot, resolve(String(rawFindingPath)))
      ? relative(normalizedRoot, resolve(String(rawFindingPath)))
      : String(rawFindingPath);
    const artifactUri = normalizedFindingPath.replaceAll("\\", "/");
    const result = {
      ruleId,
      level: severityLevel(finding.extra?.severity),
      message: { text: String(message) },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: artifactUri },
          region: {
            startLine: start.line ?? 1,
            startColumn: start.col ?? 1,
            endLine: end.line ?? start.line ?? 1,
            endColumn: end.col ?? start.col ?? 1,
          },
        },
      }],
      properties: {
        engine,
        metavars: finding.extra?.metavars ?? {},
        lines: finding.extra?.lines ?? null,
        validation_state: finding.extra?.validation_state ?? null,
      },
    };
    if (finding.extra?.fingerprint) {
      result.partialFingerprints = { semgrepFingerprint: finding.extra.fingerprint };
    }
    results.push(result);
  }
  return {
    version: "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: engine === "opengrep" ? "OpenGrep" : "Semgrep",
          version,
          informationUri: engine === "opengrep" ? "https://www.opengrep.dev/" : "https://semgrep.dev/",
          rules: [...rules.values()],
        },
      },
      invocations: [{
        executionSuccessful: (payload.errors?.length ?? 0) === 0,
        commandLine,
        properties: { errors: payload.errors ?? [] },
      }],
      results,
    }],
  };
}

async function mergeSarif(outputPath, sarif) {
  let combined = sarif;
  try {
    const existing = JSON.parse(await readFile(outputPath, "utf8"));
    if (existing.version !== "2.1.0" || !Array.isArray(existing.runs)) throw new Error("Existing SARIF has an unsupported shape");
    combined = { ...existing, runs: [...existing.runs, ...sarif.runs] };
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(combined, null, 2)}\n`, "utf8");
  return combined;
}

export async function runSemgrepScan({
  workspaceRoot,
  auditId,
  sessionId,
  agentName,
  targetPath,
  rulePaths,
  engine = "auto",
  sarifPath,
  jobs = 2,
  ruleTimeoutSeconds = 30,
  processTimeoutMs = 300_000,
  maxMemoryMb = 0,
  excludes = [],
  environment = process.env,
}) {
  if (!/^[a-z0-9][a-z0-9._-]{2,127}$/i.test(auditId)) throw new Error(`Invalid audit_id: ${auditId}`);
  if (!/^[a-z0-9][a-z0-9._:-]{2,255}$/i.test(sessionId)) throw new Error(`Invalid session_id: ${sessionId}`);
  if (!/^[a-z0-9][a-z0-9._-]{2,127}$/i.test(agentName)) throw new Error(`Invalid agent_name: ${agentName}`);
  if (!Array.isArray(rulePaths) || rulePaths.length === 0) throw new Error("At least one local rule path is required");
  const root = await realpath(resolve(workspaceRoot));
  const target = await resolveWorkspacePath(root, targetPath);
  const rules = await Promise.all(rulePaths.map(path => resolveWorkspacePath(root, path)));
  for (const rule of rules) {
    const info = await stat(rule);
    if (!info.isFile() && !info.isDirectory()) throw new Error(`Unsupported rule path: ${rule}`);
  }
  const selected = await selectEngine({ workspaceRoot: root, engine, environment });
  const args = ["scan", "--json", "--metrics=off", "--jobs", String(jobs), "--timeout", String(ruleTimeoutSeconds)];
  if (maxMemoryMb > 0) args.push("--max-memory", String(maxMemoryMb));
  for (const rule of rules) args.push("--config", rule);
  for (const pattern of excludes) {
    if (typeof pattern !== "string" || pattern.trim() === "" || pattern.includes("\0")) throw new Error("Invalid exclude pattern");
    args.push("--exclude", pattern);
  }
  args.push(target);
  const processResult = await runProcess(selected.command, args, {
    cwd: root,
    timeoutMs: processTimeoutMs,
    env: environment,
  });
  if (![0, 1].includes(processResult.code)) {
    throw new Error(`${selected.engine} scan failed with exit ${processResult.code}: ${processResult.stderr.trim()}`);
  }
  let payload;
  try {
    payload = JSON.parse(processResult.stdout);
  } catch (error) {
    throw new Error(`${selected.engine} returned invalid JSON: ${error.message}; stderr=${processResult.stderr.slice(0, 1000)}`);
  }
  const displayArgs = args.map(argument => {
    const value = String(argument);
    if (!isAbsolute(value)) return value;
    const absolute = resolve(value);
    return isInside(root, absolute) ? relative(root, absolute).replaceAll("\\", "/") || "." : value;
  });
  const commandLine = [selected.engine, ...displayArgs].join(" ");
  const rawBytes = `${JSON.stringify(payload, null, 2)}\n`;
  const rawDirectory = await resolveWorkspacePath(root, join("tmp", auditId, "semgrep", sessionId), { mustExist: false });
  await mkdir(rawDirectory, { recursive: true });
  const rawOutputPath = join(rawDirectory, `${selected.engine}.${sha256(rawBytes).slice(0, 16)}.json`);
  await writeFile(rawOutputPath, rawBytes, "utf8");

  const requestedSarif = sarifPath ?? join("reports", "sarif", `${agentName}.${sessionId}.sarif`);
  const outputPath = await resolveWorkspacePath(root, requestedSarif, { mustExist: false });
  const reportsSarifRoot = await resolveWorkspacePath(root, join("reports", "sarif"), { mustExist: false });
  if (!isInside(reportsSarifRoot, outputPath)) throw new Error("SARIF output must stay under reports/sarif/");
  const sarifRun = semgrepJsonToSarif(payload, {
    engine: selected.engine,
    version: selected.version,
    commandLine,
    workspaceRoot: root,
  });
  const combinedSarif = await mergeSarif(outputPath, sarifRun);
  const sarifBytes = `${JSON.stringify(combinedSarif, null, 2)}\n`;
  return {
    engine: selected.engine,
    version: selected.version,
    audit_id: auditId,
    session_id: sessionId,
    target_path: relative(root, target) || ".",
    rule_paths: rules.map(path => relative(root, path)),
    findings: payload.results?.length ?? 0,
    errors: payload.errors ?? [],
    raw_output_path: relative(root, rawOutputPath),
    raw_output_sha256: sha256(rawBytes),
    sarif_path: relative(root, outputPath),
    sarif_sha256: sha256(sarifBytes),
    sarif_runs: combinedSarif.runs.length,
    stderr: processResult.stderr.trim().replaceAll(root, ".") || null,
  };
}
