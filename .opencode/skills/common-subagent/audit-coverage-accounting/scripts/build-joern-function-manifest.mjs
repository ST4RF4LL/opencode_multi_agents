#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, mkdir, writeFile, rm, stat, link, copyFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { assertFrozenSources, contentDigest, FUNCTION_MANIFEST_CACHE_VERSION, printManifestResult, reusableManifest } from "./function-manifest-cache.mjs";

const LANGUAGE_CONFIG = {
  javascript: { joern: "javascript", parser_tags: ["joern-js"], owner: "web-source-auditor" },
  python: { joern: "python", parser_tags: ["joern-python"], owner: "python-source-auditor" },
  c: { joern: "c", parser_tags: ["joern-c"], owner: "c-cpp-source-auditor" },
  cpp: { joern: "c", parser_tags: ["joern-cpp"], owner: "c-cpp-source-auditor" },
  kotlin: { joern: "kotlin", parser_tags: ["joern-kotlin"], owner: "java-source-auditor" },
  jvm: { joern: "java", parser_tags: ["joern-jvm"], owner: "java-source-auditor" },
};

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const token = argv[i];
    if (!token?.startsWith("--") || argv[i + 1] == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = argv[i + 1];
  }
  for (const key of ["root", "audit-id", "scope", "language", "output"]) {
    if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  }
  if (!LANGUAGE_CONFIG[args.language]) throw new Error(`Unsupported --language: ${args.language}`);
  return args;
}

function normalizePath(path) {
  return path.split(sep).join("/").replace(/^\.\//, "");
}

function scalaString(value) {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function stableId(value) {
  return `function:${createHash("sha256").update(value).digest("hex").slice(0, 32)}`;
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 128 * 1024 * 1024, ...options });
  if (result.status !== 0) throw new Error(`${command} failed (${result.status})\n${result.stderr}\n${result.stdout}`);
  return result;
}

async function buildSourceProjection(root, projectionRoot, expected) {
  let next = 0;
  async function worker() {
    while (next < expected.length) {
      const path = expected[next];
      next += 1;
      const source = resolve(root, path);
      const target = resolve(projectionRoot, path);
      await mkdir(dirname(target), { recursive: true });
      try {
        await link(source, target);
      } catch (error) {
        if (!["EXDEV", "EPERM", "EACCES", "ENOTSUP"].includes(error.code)) throw error;
        await copyFile(source, target);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(16, expected.length) }, worker));
}

function buildQuery(rawOutputPath) {
  return `
import java.io.PrintWriter
import java.io.File

def esc(value: String): String = value
  .replace("\\\\", "\\\\\\\\")
  .replace("\\\"", "\\\\\\\"")
  .replace("\\n", "\\\\n")
  .replace("\\r", "\\\\r")
  .replace("\\t", "\\\\t")

val inventoryWriter = new PrintWriter(new File(${scalaString(rawOutputPath)}), "UTF-8")
cpg.file.name.l.distinct.sorted.foreach { fileName =>
  inventoryWriter.println(s"FILE\\t{\\\"path\\\":\\\"${"${esc(fileName)}"}\\\"}")
}
cpg.method.filterNot(_.isExternal).l.sortBy(m => (m.filename, m.lineNumber.getOrElse(-1), m.fullName)).foreach { method =>
  val fileName = esc(method.filename)
  val name = esc(method.name)
  val fullName = esc(method.fullName)
  val signature = esc(method.signature)
  val code = esc(method.code)
  val lineStart = method.lineNumber.getOrElse(-1)
  val lineEnd = method.lineNumberEnd.getOrElse(lineStart)
  inventoryWriter.println(s"FUNCTION\\t{\\\"path\\\":\\\"$fileName\\\",\\\"kind\\\":\\\"method\\\",\\\"name\\\":\\\"$name\\\",\\\"qualified_name\\\":\\\"$fullName\\\",\\\"signature\\\":\\\"$signature\\\",\\\"line_start\\\":$lineStart,\\\"line_end\\\":$lineEnd,\\\"code\\\":\\\"$code\\\"}")
}
inventoryWriter.close()
println("coverage_inventory_export_complete")
`;
}

function normalizeCpgPath(root, value) {
  if (!value || value === "<unknown>" || value === "N/A") return value;
  const cleaned = value.replace(/^file:\/\//, "");
  const absolute = isAbsolute(cleaned) ? resolve(cleaned) : resolve(root, cleaned);
  const rel = relative(root, absolute);
  if (!rel.startsWith("..") && !isAbsolute(rel)) return normalizePath(rel);
  return normalizePath(cleaned);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const config = LANGUAGE_CONFIG[args.language];
  const root = resolve(args.root);
  const scopePath = resolve(args.scope);
  const outputPath = resolve(args.output);
  const scope = JSON.parse(await readFile(scopePath, "utf8"));
  if (scope.audit_id !== args["audit-id"]) throw new Error("Scope manifest audit_id mismatch");
  if (!scope.complete) throw new Error("Scope manifest is incomplete");
  if (scope.manifest_digest !== contentDigest(scope)) throw new Error("Scope manifest content digest is invalid");

  const expected = scope.files.filter(file => config.parser_tags.includes(file.function_parser)).map(file => file.path).sort();
  await assertFrozenSources(root, scope, expected);
  const cached = await reusableManifest(outputPath, {
    auditId: args["audit-id"],
    scopeDigest: scope.scope_digest,
    language: args.language,
    expected,
    force: args.force === "true",
  });
  if (cached) {
    printManifestResult(outputPath, cached, true);
    return;
  }
  const workDir = resolve(dirname(outputPath), `.joern-inventory-${args.language}`);
  const projectionRoot = resolve(workDir, "source");
  const cpgPath = resolve(workDir, "cpg.bin");
  const queryPath = resolve(workDir, "export-inventory.sc");
  const rawPath = resolve(workDir, "inventory.ndjson");
  await rm(workDir, { recursive: true, force: true });
  await mkdir(workDir, { recursive: true });

  if (expected.length > 0) {
    await buildSourceProjection(root, projectionRoot, expected);
    const parseResult = run(process.env.JOERN_PARSE_BIN || "/usr/local/bin/joern-parse", [projectionRoot, "-o", cpgPath, "--language", config.joern]);
    let cpgStat;
    try { cpgStat = await stat(cpgPath); } catch { cpgStat = null; }
    if (!cpgStat || cpgStat.size === 0 || /Exception|NoSuchElementException/.test(`${parseResult.stdout}\n${parseResult.stderr}`)) {
      throw new Error(`Joern did not produce a valid CPG\n${parseResult.stderr}\n${parseResult.stdout}`);
    }
    await writeFile(queryPath, buildQuery(rawPath), "utf8");
    run(process.env.JOERN_BIN || "/usr/local/bin/joern", [cpgPath, "--script", queryPath]);
  } else {
    await writeFile(rawPath, "", "utf8");
  }

  const cpgFiles = [];
  const functions = [];
  const raw = await readFile(rawPath, "utf8");
  for (const [index, line] of raw.split(/\r?\n/).entries()) {
    if (!line) continue;
    const tab = line.indexOf("\t");
    if (tab < 1) throw new Error(`Malformed Joern inventory line ${index + 1}`);
    const kind = line.slice(0, tab);
    const record = JSON.parse(line.slice(tab + 1));
    record.path = normalizeCpgPath(projectionRoot, record.path);
    if (kind === "FILE") cpgFiles.push(record.path);
    else if (kind === "FUNCTION") {
      const identity = [args.language, record.path, record.kind, record.qualified_name, record.signature, record.line_start].join("|");
      const codeSha = createHash("sha256").update(record.code ?? "").digest("hex");
      delete record.code;
      functions.push({ function_id: stableId(identity), language: args.language, owner_agent: config.owner, required_lenses: ["sink-driven", "control-driven", "config-driven"], code_sha256: codeSha, ...record });
    } else throw new Error(`Unknown inventory record: ${kind}`);
  }

  const expectedSet = new Set(expected);
  const parsedSet = new Set(cpgFiles.filter(path => expectedSet.has(path)));
  const missingFiles = expected.filter(path => !parsedSet.has(path));
  const unexpectedFiles = [...new Set(cpgFiles.filter(path => !expectedSet.has(path)))].sort();
  const inScopeFunctions = functions.filter(item => expectedSet.has(item.path)).sort((a, b) => a.path.localeCompare(b.path) || a.line_start - b.line_start || a.qualified_name.localeCompare(b.qualified_name));
  const manifest = {
    schema_version: 1,
    audit_id: args["audit-id"],
    language: args.language,
    extractor: { name: "joern-cpg", frontend_language: config.joern, input_mode: "scoped-source-projection", cache_version: FUNCTION_MANIFEST_CACHE_VERSION },
    scope_manifest: scopePath,
    scope_digest: scope.scope_digest,
    expected_files: expected,
    parsed_files: [...parsedSet].sort(),
    missing_files: missingFiles,
    unexpected_cpg_files: unexpectedFiles,
    functions: inScopeFunctions,
    summary: { expected_files: expected.length, parsed_files: parsedSet.size, functions: inScopeFunctions.length, missing_files: missingFiles.length, unexpected_cpg_files: unexpectedFiles.length },
    complete: missingFiles.length === 0,
  };
  manifest.manifest_digest = createHash("sha256").update(JSON.stringify(manifest)).digest("hex");

  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  await rm(workDir, { recursive: true, force: true });
  printManifestResult(outputPath, manifest, false);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
