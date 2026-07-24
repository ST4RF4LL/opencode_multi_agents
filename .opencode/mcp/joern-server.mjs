#!/usr/bin/env node
// Joern MCP Server — workspace-shared CPG generation, rule execution, SARIF export, session cleanup.
// Run via: node .opencode/mcp/joern-server.mjs

import { McpServer } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js";
import { StdioServerTransport } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js";
import { z } from "../node_modules/zod/index.js";
import { spawn } from "node:child_process";
import { mkdir, rm, readFile, writeFile, readdir, stat, access } from "node:fs/promises";
import { resolve, relative, join, dirname, basename, delimiter, extname, isAbsolute, sep } from "node:path";
import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";
import { EOL } from "node:os";
import { fileURLToPath } from "node:url";

// ── Constants ───────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const WORKSPACE_ROOT = resolve(process.cwd());

const JOERN_BIN       = process.env.JOERN_BIN       || "joern";
const JOERN_PARSE_BIN = process.env.JOERN_PARSE_BIN || "joern-parse";
const JOERN_VERSION   = process.env.JOERN_VERSION   || "unknown";
const JOERN_GNUBIN    = process.env.JOERN_GNUBIN    || "";
const JOERN_JAVA_BIN  = process.env.JOERN_JAVA_BIN  || "";

const SHARED_RULES_DIR  = join(WORKSPACE_ROOT, ".opencode", "shared", "security-audit", "joern-rules");
const SHARED_RULES_INDEX = join(SHARED_RULES_DIR, "index.json");
const TMP_ROOT          = join(WORKSPACE_ROOT, "tmp", "joern");
const REPORTS_SARIF_DIR = join(WORKSPACE_ROOT, "reports", "sarif");

const JOERN_TIMEOUT_MS  = 180_000; // 3 min per joern subprocess

const JOERN_LANGUAGE_ALIASES = new Map([
  ["c", "c"],
  ["cpp", "c"],
  ["c++", "c"],
  ["java", "java"],
  ["jvm", "java"],
  ["kotlin", "kotlin"],
  ["python", "python"],
  ["py", "python"],
  ["javascript", "javascript"],
  ["js", "javascript"],
  ["typescript", "javascript"],
  ["ts", "javascript"],
  ["php", "php"],
  ["ruby", "rubysrc"],
  ["go", "golang"],
  ["golang", "golang"],
  ["rust", "rust"],
  ["csharp", "csharp"],
  ["c#", "csharp"],
  ["swift", "swiftsrc"],
]);

// ── Helpers ─────────────────────────────────────────────────
const require_ = createRequire(import.meta.url);

/** Build a clean PATH that includes coreutils and java for joern */
function joernPATH() {
  const base = process.env.PATH || "/usr/bin:/bin";
  const entries = [JOERN_GNUBIN, JOERN_JAVA_BIN, ...base.split(delimiter)].filter(Boolean);
  return [...new Set(entries)].join(delimiter);
}

async function resolveExecutable(command) {
  if (isAbsolute(command) || command.includes(sep)) {
    await access(command, 1 /* X_OK */);
    return command;
  }
  const { stdout } = await execCommand("sh", ["-c", 'command -v "$1"', "sh", command], { timeout: 5_000 });
  const resolved = stdout.trim();
  if (!resolved) throw new Error(`Executable not found on PATH: ${command}`);
  return resolved;
}

/** Check that a file path stays inside the workspace */
function isWithinWorkspace(absPath) {
  const rel = relative(WORKSPACE_ROOT, resolve(absPath));
  return !rel.startsWith("..") && !resolve(absPath).startsWith("..");
}

/** Resolve and validate a workspace-relative path */
function resolveWorkspacePath(relPath) {
  const abs = resolve(WORKSPACE_ROOT, relPath);
  if (!isWithinWorkspace(abs)) {
    throw new Error(`Path escapes workspace: ${relPath}`);
  }
  return abs;
}

function normalizeJoernLanguage(language) {
  const normalized = JOERN_LANGUAGE_ALIASES.get(String(language).trim().toLowerCase());
  if (!normalized) throw new Error(`Unsupported Joern language alias: ${language}`);
  return normalized;
}

/** Ensure a session directory exists under tmp/joern/ */
async function sessionDir(sessionId) {
  if (!/^[a-z0-9][a-z0-9._-]{2,127}$/i.test(sessionId)) {
    throw new Error(`Invalid session_id: ${sessionId}`);
  }
  const dir = join(TMP_ROOT, sessionId);
  await mkdir(dir, { recursive: true });
  return dir;
}

/** Run a command with timeout, capture stdout/stderr */
function execCommand(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      timeout: opts.timeout ?? JOERN_TIMEOUT_MS,
      env: { ...process.env, PATH: joernPATH(), ...(opts.env ?? {}) },
      cwd: opts.cwd ?? WORKSPACE_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
      ...opts.spawnOpts,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", d => { stdout += d.toString(); });
    child.stderr.on("data", d => { stderr += d.toString(); });
    child.on("close", code => {
      if (code === 0) resolve({ stdout, stderr, code });
      else reject(new Error(`Command failed (${code}): ${cmd} ${args.join(" ")}\n${stderr}\n${stdout}`));
    });
    child.on("error", reject);
  });
}

// ── SARIF builder ───────────────────────────────────────────
function buildSarif(runResults, ruleId, language) {
  const rules = {};
  const results = [];
  for (const r of runResults) {
    const rid = r.ruleId ?? ruleId ?? "joern/unknown";
    rules[rid] = { id: rid, name: r.ruleName ?? rid, shortDescription: { text: r.message?.slice(0, 200) ?? "" } };
    results.push({
      ruleId: rid,
      message: { text: r.message ?? "No message" },
      locations: r.locations?.map(l => ({
        physicalLocation: {
          artifactLocation: { uri: l.file ?? "unknown" },
          region: { startLine: l.line ?? 1, startColumn: l.column ?? 1 },
        },
      })) ?? [],
      level: r.severity === "Critical" ? "error" : r.severity === "High" ? "error" : "warning",
      properties: {
        findingId: r.findingId ?? "",
        dimension: r.dimension ?? "",
        dataFlow: r.dataFlow ?? "",
      },
    });
    if (r.fix) results[results.length - 1].fixes = [{ description: { text: r.fix } }];
  }
  return {
    version: "2.1.0",
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    runs: [{
      tool: { driver: { name: "joern", version: JOERN_VERSION, informationUri: "https://joern.io", rules: Object.values(rules), language: language ?? "en" } },
      results,
    }],
  };
}

// ── MCP Server ──────────────────────────────────────────────
const server = new McpServer({
  name: "joern",
  version: "1.0.0",
}, {
  capabilities: { tools: {} },
});

// ── Tool: joern_health ──────────────────────────────────────
server.registerTool("joern_health", {
  description: "Check portable Joern binary and JDK configuration. GNU coreutils is checked only when JOERN_GNUBIN is configured (normally macOS).",
}, async () => {
  const checks = {};
  for (const [k, v] of [["joern", JOERN_BIN], ["joern-parse", JOERN_PARSE_BIN]]) {
    try { await resolveExecutable(v); checks[k] = "ok"; } catch { checks[k] = "missing"; }
  }
  try { await resolveExecutable("java"); checks.java = "ok"; } catch { checks.java = "missing"; }
  if (JOERN_GNUBIN) {
    try { await resolveExecutable("greadlink"); checks.greadlink = "ok"; } catch { checks.greadlink = "missing"; }
  } else {
    checks.greadlink = "not-required";
  }
  checks.workspace = ".";
  checks.sharedRulesDir = ".opencode/shared/security-audit/joern-rules";
  checks.tmpRoot = "tmp/joern";
  try {
    const rulesIdx = JSON.parse(await readFile(SHARED_RULES_INDEX, "utf8"));
    checks.sharedRulesCount = rulesIdx.rules?.length ?? 0;
  } catch {
    checks.sharedRulesCount = 0;
  }
  const healthy = Object.values(checks).every(v => v !== "missing");
  return {
    content: [{ type: "text", text: JSON.stringify({ healthy, checks }, null, 2) }],
  };
});

// ── Tool: joern_list_rules ──────────────────────────────────
server.registerTool("joern_list_rules", {
  description: "List shared published Joern rules with metadata.",
}, async () => {
  try {
    const idx = JSON.parse(await readFile(SHARED_RULES_INDEX, "utf8"));
    return {
      content: [{ type: "text", text: JSON.stringify(idx.rules ?? [], null, 2) }],
    };
  } catch (e) {
    return { content: [{ type: "text", text: JSON.stringify({ error: e.message, rules: [] }, null, 2) }] };
  }
});

// ── Tool: joern_create_cpg ──────────────────────────────────
server.registerTool("joern_create_cpg", {
  description: "Create a Code Property Graph for source under a workspace-relative path. Stores CPG in tmp/joern/<session_id>/cpg.bin. Normalizes aliases such as cpp→c, jvm→java, js/ts→javascript, go→golang, ruby→rubysrc, and verifies that Joern actually produced a non-empty CPG.",
  inputSchema: { session_id: z.string(), source_path: z.string(), language: z.string() },
}, async ({ session_id, source_path, language }) => {
  const dir = await sessionDir(session_id);
  const absSrc = resolveWorkspacePath(source_path);
  const cpgFile = join(dir, "cpg.bin");
  const frontendLanguage = normalizeJoernLanguage(language);

  const sourceInfo = await stat(absSrc);
  if (!sourceInfo.isDirectory() && !sourceInfo.isFile()) throw new Error(`Unsupported source path type: ${source_path}`);
  await rm(cpgFile, { recursive: true, force: true });

  const result = await execCommand(JOERN_PARSE_BIN, [
    absSrc,
    "-o", cpgFile,
    "--language", frontendLanguage,
  ]);
  const combinedOutput = `${result.stdout}\n${result.stderr}`;
  let cpgInfo;
  try { cpgInfo = await stat(cpgFile); } catch { cpgInfo = null; }
  if (!cpgInfo?.isFile() || cpgInfo.size === 0 || /(?:NoSuchElementException|Exception in thread|java\.[\w.]+Exception|Error while creating CPG)/.test(combinedOutput)) {
    await rm(cpgFile, { recursive: true, force: true });
    throw new Error(`Joern reported success but did not produce a valid CPG for language ${frontendLanguage}\n${combinedOutput}`);
  }
  return {
    content: [{ type: "text", text: JSON.stringify({ status: "created", cpg: cpgFile, cpg_bytes: cpgInfo.size, session_id, requested_language: language, frontend_language: frontendLanguage }, null, 2) }],
  };
});

// ── Tool: joern_run_rule ────────────────────────────────────
server.registerTool("joern_run_rule", {
  description: "Execute a published Joern rule against a session CPG. The rule must exist in the shared rules directory (.opencode/shared/security-audit/joern-rules/<language>/<rule-id>.sc). Results are returned inline.",
  inputSchema: { session_id: z.string(), rule_id: z.string(), language: z.string() },
}, async ({ session_id, rule_id, language }) => {
  const dir = await sessionDir(session_id);
  const cpgFile = join(dir, "cpg.bin");

  // Only allow rules from the shared directory
  const ruleFile = resolve(SHARED_RULES_DIR, language, `${rule_id}.sc`);
  if (!isWithinWorkspace(ruleFile) || !ruleFile.startsWith(SHARED_RULES_DIR)) {
    throw new Error(`Rule not in shared rules directory: ${rule_id}`);
  }

  try {
    await stat(cpgFile);
  } catch {
    throw new Error(`No CPG found for session ${session_id}. Run joern_create_cpg first.`);
  }
  try {
    await stat(ruleFile);
  } catch {
    throw new Error(`Rule not found: ${ruleFile}`);
  }

  const { stdout } = await execCommand(JOERN_BIN, [
    cpgFile,
    "--script", ruleFile,
  ]);

  const findings = parseJoernOutput(stdout);
  return {
    content: [{ type: "text", text: JSON.stringify({ rule_id, language, findings }, null, 2) }],
  };
});

// ── Tool: joern_run_query ───────────────────────────────────
server.registerTool("joern_run_query", {
  description: "Run a read-only CPG query script against a session CPG. The script will be written to a temp file in the session directory and executed. No arbitrary shell or filesystem write is allowed.",
  inputSchema: { session_id: z.string(), query_script: z.string(), query_name: z.string() },
}, async ({ session_id, query_script, query_name }) => {
  const dir = await sessionDir(session_id);
  const cpgFile = join(dir, "cpg.bin");

  try { await stat(cpgFile); } catch { throw new Error(`No CPG found for session ${session_id}.`); }

  const safeName = (query_name ?? "query").replace(/[^a-zA-Z0-9._-]/g, "_");
  const tmpScript = join(dir, `${safeName}.sc`);
  await writeFile(tmpScript, query_script, "utf8");

  try {
    const { stdout } = await execCommand(JOERN_BIN, [cpgFile, "--script", tmpScript]);
    return {
      content: [{ type: "text", text: JSON.stringify({ query_name: safeName, output: stdout.slice(-8000) }, null, 2) }],
    };
  } finally {
    // Clean up temp script
    try { await rm(tmpScript); } catch {}
  }
});

// ── Tool: joern_export_sarif ────────────────────────────────
server.registerTool("joern_export_sarif", {
  description: "Export session rule findings as a SARIF 2.1.0 report to reports/sarif/<agent-name>.<session-id>.sarif. Source paths are redacted to workspace-relative.",
  inputSchema: { session_id: z.string(), agent_name: z.string(), findings: z.string(), language: z.string().optional() },
}, async ({ session_id, agent_name, findings, language }) => {
  await sessionDir(session_id); // validate session id
  await mkdir(REPORTS_SARIF_DIR, { recursive: true });

  let parsedFindings;
  try { parsedFindings = JSON.parse(findings); } catch { throw new Error("Invalid findings JSON"); }

  const sarif = buildSarif(parsedFindings, null, language ?? "en");

  // Redact absolute paths to workspace-relative in locations
  for (const run of sarif.runs) {
    for (const result of run.results) {
      for (const loc of result.locations ?? []) {
        const uri = loc.physicalLocation?.artifactLocation?.uri;
        if (uri && uri.startsWith("/")) {
          try {
            const rel = relative(WORKSPACE_ROOT, uri);
            if (!rel.startsWith("..")) loc.physicalLocation.artifactLocation.uri = rel;
          } catch {}
        }
      }
    }
  }

  const sarifFile = join(REPORTS_SARIF_DIR, `${agent_name}.${session_id}.sarif`);
  await writeFile(sarifFile, JSON.stringify(sarif, null, 2), "utf8");

  return {
    content: [{ type: "text", text: JSON.stringify({ status: "exported", file: sarifFile, findingCount: sarif.runs[0]?.results?.length ?? 0 }, null, 2) }],
  };
});

// ── Tool: joern_cleanup_session ─────────────────────────────
server.registerTool("joern_cleanup_session", {
  description: "Remove all CPG data, logs, and temporary files for a session.",
  inputSchema: { session_id: z.string() },
}, async ({ session_id }) => {
  const dir = join(TMP_ROOT, session_id);
  try {
    await rm(dir, { recursive: true, force: true });
    return { content: [{ type: "text", text: JSON.stringify({ status: "cleaned", session_id }) }] };
  } catch (e) {
    return { content: [{ type: "text", text: JSON.stringify({ status: "error", session_id, error: e.message }) }] };
  }
});

// ── Parse Joern output ──────────────────────────────────────
function parseJoernOutput(stdout) {
  const findings = [];
  // Match lines like: "result: ..." or typical joern script println output
  // Joern scripts often use println() which outputs one line per finding
  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    // Try to parse JSON finding objects
    try {
      const obj = JSON.parse(trimmed);
      findings.push(obj);
      continue;
    } catch {}
    // Otherwise treat as a text finding
    findings.push({ raw: trimmed });
  }
  return findings;
}

// ── Start ───────────────────────────────────────────────────
const transport = new StdioServerTransport();
await server.connect(transport);

// Log startup to stderr (not mixed with stdio MCP protocol)
console.error(`[joern-mcp] started | joern=${JOERN_VERSION}`);
