#!/usr/bin/env node

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, opendir, readlink, mkdir, writeFile } from "node:fs/promises";
import { dirname, extname, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";

const SCHEMA_VERSION = 1;
const LENSES = ["sink-driven", "control-driven", "config-driven"];
const INFRASTRUCTURE_EXCLUSIONS = new Map([
  [".git", "version-control-internals"],
  [".opencode", "audit-infrastructure"],
  ["reports", "audit-output"],
  ["tmp", "audit-runtime-output"],
]);

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) throw new Error(`Unexpected argument: ${token}`);
    const key = token.slice(2);
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for --${key}`);
    args[key] = value;
    i += 1;
  }
  for (const key of ["root", "audit-id", "output"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  }
  if (!/^[a-z0-9][a-z0-9._-]{2,127}$/i.test(args["audit-id"])) {
    throw new Error("Invalid --audit-id");
  }
  return args;
}

function normalizePath(path) {
  return path.split(sep).join("/").replace(/^\.\//, "");
}

function stableId(prefix, value) {
  return `${prefix}:${createHash("sha256").update(value).digest("hex").slice(0, 24)}`;
}

async function sha256File(path) {
  return await new Promise((resolveHash, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("data", chunk => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolveHash(hash.digest("hex")));
  });
}

async function looksBinary(path, size) {
  if (size === 0) return false;
  const handle = await import("node:fs/promises").then(m => m.open(path, "r"));
  try {
    const length = Math.min(size, 8192);
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, 0);
    for (let i = 0; i < bytesRead; i += 1) {
      if (buffer[i] === 0) return true;
    }
    return false;
  } finally {
    await handle.close();
  }
}

const CLASSIFIERS = [
  { exts: [".java"], owner: "java-source-auditor", kind: "source", parser: "javac-java" },
  { exts: [".kt", ".kts"], owner: "java-source-auditor", kind: "source", parser: "joern-kotlin" },
  { exts: [".groovy"], owner: "java-source-auditor", kind: "source", parser: null, inventoryState: "unsupported", inventoryReason: "no-configured-groovy-ast-cpg-extractor" },
  { exts: [".scala"], owner: "java-source-auditor", kind: "source", parser: null, inventoryState: "unsupported", inventoryReason: "no-configured-scala-ast-cpg-extractor" },
  { exts: [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"], owner: "web-source-auditor", kind: "source", parser: "joern-js" },
  { exts: [".jsp", ".jspx", ".html", ".htm", ".ftl", ".ftlh", ".vm", ".mustache", ".hbs", ".vue", ".svelte"], owner: "web-source-auditor", kind: "template", parser: "embedded-web" },
  { exts: [".css", ".scss", ".sass", ".less"], owner: "web-source-auditor", kind: "web-resource", parser: null },
  { exts: [".py", ".pyw"], owner: "python-source-auditor", kind: "source", parser: "joern-python" },
  { exts: [".c", ".h"], owner: "c-cpp-source-auditor", kind: "source", parser: "joern-c" },
  { exts: [".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"], owner: "c-cpp-source-auditor", kind: "source", parser: "joern-cpp" },
  { exts: [".gradle"], owner: "platform-security-auditor", kind: "build-source", parser: null, inventoryState: "unsupported", inventoryReason: "no-configured-groovy-ast-cpg-extractor" },
  { exts: [".sql"], owner: "platform-security-auditor", kind: "database-source", parser: null, inventoryState: "unsupported", inventoryReason: "no-configured-sql-procedure-ast-extractor" },
  { exts: [".xml", ".yml", ".yaml", ".json", ".json5", ".toml", ".ini", ".conf", ".cfg", ".properties", ".env", ".tf", ".hcl"], owner: "platform-security-auditor", kind: "configuration", parser: null },
  { exts: [".md", ".adoc", ".rst", ".txt"], owner: "platform-security-auditor", kind: "documentation", parser: null },
];

function classify(path, binary) {
  if (binary) return { owner_agent: "platform-security-auditor", content_kind: "binary", parser: null, inventory_state: "not-applicable", inventory_reason: "binary-artifact-outside-source-function-universe" };
  const base = path.toLowerCase().split("/").at(-1);
  if (base === "jenkinsfile") {
    return { owner_agent: "platform-security-auditor", content_kind: "build-source", parser: null, inventory_state: "unsupported", inventory_reason: "no-configured-groovy-ast-cpg-extractor" };
  }
  if (["dockerfile", "makefile", "procfile", "pom.xml"].includes(base)) {
    return { owner_agent: "platform-security-auditor", content_kind: "configuration", parser: null, inventory_state: "not-applicable", inventory_reason: "declarative-build-or-runtime-configuration" };
  }
  const ext = extname(base);
  const hit = CLASSIFIERS.find(item => item.exts.includes(ext));
  if (hit) return {
    owner_agent: hit.owner,
    content_kind: hit.kind,
    parser: hit.parser,
    inventory_state: hit.inventoryState ?? (hit.parser ? "required" : "not-applicable"),
    inventory_reason: hit.inventoryReason ?? (hit.parser ? "configured-ast-or-cpg-extractor" : "known-non-function-source-type"),
  };
  return { owner_agent: "platform-security-auditor", content_kind: "unknown-text", parser: null, inventory_state: "unsupported", inventory_reason: "unknown-text-may-contain-uninventoried-functions" };
}

function gitTrackedFiles(root) {
  const result = spawnSync("git", ["-C", root, "ls-files", "-z", "--cached"], { encoding: "buffer" });
  if (result.status !== 0) return new Set();
  return new Set(result.stdout.toString("utf8").split("\0").filter(Boolean).map(normalizePath));
}

async function walk(root) {
  const files = [];
  const symlinks = [];
  const exclusions = [];
  const errors = [];

  async function visit(absDir, relDir) {
    let dir;
    try {
      dir = await opendir(absDir);
    } catch (error) {
      errors.push({ path: relDir || ".", operation: "opendir", error: error.message });
      return;
    }
    const entries = [];
    for await (const entry of dir) entries.push(entry);
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const rel = normalizePath(relDir ? `${relDir}/${entry.name}` : entry.name);
      const abs = resolve(absDir, entry.name);
      if (entry.name === ".git") {
        exclusions.push({ path: rel, reason: "version-control-internals" });
        continue;
      }
      if (!relDir && entry.isDirectory() && INFRASTRUCTURE_EXCLUSIONS.has(entry.name)) {
        exclusions.push({ path: rel, reason: INFRASTRUCTURE_EXCLUSIONS.get(entry.name) });
        continue;
      }
      try {
        const info = await lstat(abs);
        if (info.isSymbolicLink()) {
          symlinks.push({
            file_id: stableId("file", rel),
            path: rel,
            type: "symlink",
            link_target: await readlink(abs),
            size: info.size,
            owner_agent: "platform-security-auditor",
            content_kind: "symlink",
            function_parser: null,
            function_inventory_state: "not-applicable",
            function_inventory_reason: "symlink-not-followed-file-target-reviewed-separately-if-in-scope",
            function_inventory_required: false,
            review_required: true,
            required_lenses: LENSES,
          });
        } else if (info.isDirectory()) {
          await visit(abs, rel);
        } else if (info.isFile()) {
          files.push({ abs, rel, info });
        } else {
          errors.push({ path: rel, operation: "classify", error: "unsupported-filesystem-entry" });
        }
      } catch (error) {
        errors.push({ path: rel, operation: "lstat", error: error.message });
      }
    }
  }

  await visit(root, "");
  return { files, symlinks, exclusions, errors };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = resolve(args.root);
  const output = resolve(args.output);
  const tracked = gitTrackedFiles(root);
  const walked = await walk(root);
  const records = [...walked.symlinks];

  for (const item of walked.files) {
    try {
      const binary = await looksBinary(item.abs, item.info.size);
      const classification = classify(item.rel, binary);
      records.push({
        file_id: stableId("file", item.rel),
        path: item.rel,
        type: "file",
        size: item.info.size,
        sha256: await sha256File(item.abs),
        tracked_by_git: tracked.has(item.rel),
        owner_agent: classification.owner_agent,
        content_kind: classification.content_kind,
        function_parser: classification.parser,
        function_inventory_state: classification.inventory_state,
        function_inventory_reason: classification.inventory_reason,
        function_inventory_required: classification.inventory_state === "required",
        review_required: true,
        required_lenses: LENSES,
      });
    } catch (error) {
      walked.errors.push({ path: item.rel, operation: "read-or-hash", error: error.message });
    }
  }

  records.sort((a, b) => a.path.localeCompare(b.path));
  const digestInput = records.map(r => `${r.path}\0${r.type}\0${r.sha256 ?? r.link_target ?? ""}`).join("\n");
  const manifest = {
    schema_version: SCHEMA_VERSION,
    audit_id: args["audit-id"],
    root,
    scope_digest: createHash("sha256").update(digestInput).digest("hex"),
    policy: {
      enumeration: "recursive-filesystem-walk",
      excluded_root_directories: Object.fromEntries(INFRASTRUCTURE_EXCLUSIONS),
      all_discovered_files_require_review: true,
      lenses: LENSES,
    },
    summary: {
      files: records.length,
      regular_files: records.filter(r => r.type === "file").length,
      symlinks: records.filter(r => r.type === "symlink").length,
      function_inventory_required: records.filter(r => r.function_inventory_required).length,
      function_inventory_unsupported: records.filter(r => r.function_inventory_state === "unsupported").length,
      untracked_files: records.filter(r => r.type === "file" && !r.tracked_by_git).length,
      exclusions: walked.exclusions.length,
      errors: walked.errors.length,
    },
    files: records,
    exclusions: walked.exclusions,
    errors: walked.errors,
    complete: walked.errors.length === 0,
  };
  manifest.manifest_digest = createHash("sha256").update(JSON.stringify(manifest)).digest("hex");

  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output, ...manifest.summary, complete: manifest.complete })}\n`);
  if (!manifest.complete) process.exitCode = 2;
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
