#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, mkdir, writeFile, rm } from "node:fs/promises";
import { dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { assertFrozenSources, contentDigest, FUNCTION_MANIFEST_CACHE_VERSION, printManifestResult, reusableManifest } from "./function-manifest-cache.mjs";

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const token = argv[i];
    if (!token?.startsWith("--") || argv[i + 1] == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = argv[i + 1];
  }
  for (const key of ["root", "audit-id", "scope", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

function stableId(value) {
  return `function:${createHash("sha256").update(value).digest("hex").slice(0, 32)}`;
}

function lineAt(text, offset) {
  let line = 1;
  for (let i = 0; i < offset; i += 1) if (text.charCodeAt(i) === 10) line += 1;
  return line;
}

function codeSha(value) {
  return createHash("sha256").update(value).digest("hex");
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 128 * 1024 * 1024, ...options });
  if (result.status !== 0) throw new Error(`${command} failed (${result.status})\n${result.stderr}\n${result.stdout}`);
  return result;
}

function addUnit(units, file, kind, name, lineStart, code, ordinal = 0) {
  const qualified = `${file}::${kind}:${name}@${lineStart}:${ordinal}`;
  units.push({
    function_id: stableId(["embedded-web", qualified].join("|")),
    language: "embedded-web",
    owner_agent: "web-source-auditor",
    required_lenses: ["sink-driven", "control-driven", "config-driven"],
    path: file,
    kind,
    name,
    qualified_name: qualified,
    signature: name,
    line_start: lineStart,
    line_end: lineStart + (code.match(/\n/g)?.length ?? 0),
    code_sha256: codeSha(code),
  });
}

function parseTemplateUnits(path, text, units, scriptBlocks) {
  let ordinal = 0;
  const scriptPattern = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  for (const match of text.matchAll(scriptPattern)) {
    const attrs = match[1] ?? "";
    const body = match[2] ?? "";
    const type = /\btype\s*=\s*["']([^"']+)["']/i.exec(attrs)?.[1]?.toLowerCase() ?? "";
    const lang = /\blang\s*=\s*["']([^"']+)["']/i.exec(attrs)?.[1]?.toLowerCase() ?? "";
    const external = /\bsrc\s*=/i.test(attrs);
    const executable = !external && (!type || ["text/javascript", "application/javascript", "module", "text/typescript"].includes(type));
    const bodyOffset = match.index + match[0].indexOf(body);
    const startLine = lineAt(text, bodyOffset);
    if (executable && body.trim()) {
      const extension = lang.includes("ts") || type.includes("typescript") ? ".ts" : ".js";
      scriptBlocks.push({ original_path: path, start_line: startLine, code: body, extension, ordinal: ordinal++ });
    } else if (body.trim()) {
      addUnit(units, path, "non-javascript-script-block", type || "script", startLine, body, ordinal++);
    }
  }

  const macroPatterns = [
    { kind: "freemarker-macro", regex: /<#macro\s+([A-Za-z_][\w.-]*)\b/gi },
    { kind: "freemarker-function", regex: /<#function\s+([A-Za-z_][\w.-]*)\b/gi },
    { kind: "velocity-macro", regex: /#macro\s*\(\s*([A-Za-z_][\w.-]*)\b/gi },
  ];
  for (const { kind, regex } of macroPatterns) {
    for (const match of text.matchAll(regex)) addUnit(units, path, kind, match[1], lineAt(text, match.index), match[0], ordinal++);
  }

  const handlerPatterns = [
    { kind: "html-event-handler", regex: /\b(on[a-z][\w:-]*)\s*=\s*(["'])([\s\S]*?)\2/gi, nameGroup: 1, codeGroup: 3 },
    { kind: "framework-event-expression", regex: /(?:\bv-on:|\B@|\bon:)([a-z][\w:-]*)\s*=\s*(["'])([\s\S]*?)\2/gi, nameGroup: 1, codeGroup: 3 },
    { kind: "javascript-url-handler", regex: /\b(href|src|action|formaction)\s*=\s*(["'])\s*javascript:([\s\S]*?)\2/gi, nameGroup: 1, codeGroup: 3 },
  ];
  for (const { kind, regex, nameGroup, codeGroup } of handlerPatterns) {
    for (const match of text.matchAll(regex)) {
      const code = match[codeGroup] ?? "";
      const codeOffset = match.index + match[0].indexOf(code);
      addUnit(units, path, kind, match[nameGroup], lineAt(text, codeOffset), code, ordinal++);
    }
  }

  if ([".jsp", ".jspx"].includes(extname(path).toLowerCase())) {
    const jspPattern = /<%(?!@|--|=)(!?)([\s\S]*?)%>/g;
    for (const match of text.matchAll(jspPattern)) {
      const declaration = match[1] === "!";
      addUnit(units, path, declaration ? "jsp-declaration-block" : "jsp-service-block", declaration ? "declaration" : "_jspService", lineAt(text, match.index), match[2] ?? "", ordinal++);
    }
    const jspExpressionPattern = /<%=([\s\S]*?)%>/g;
    for (const match of text.matchAll(jspExpressionPattern)) {
      addUnit(units, path, "jsp-expression-block", "_jspService-expression", lineAt(text, match.index), match[1] ?? "", ordinal++);
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = resolve(args.root);
  const scopePath = resolve(args.scope);
  const outputPath = resolve(args.output);
  const scope = JSON.parse(await readFile(scopePath, "utf8"));
  if (scope.audit_id !== args["audit-id"]) throw new Error("Scope manifest audit_id mismatch");
  if (!scope.complete) throw new Error("Scope manifest is incomplete");
  if (scope.manifest_digest !== contentDigest(scope)) throw new Error("Scope manifest content digest is invalid");

  const expected = scope.files.filter(file => file.function_parser === "embedded-web").map(file => file.path).sort();
  await assertFrozenSources(root, scope, expected);
  const cached = await reusableManifest(outputPath, {
    auditId: args["audit-id"],
    scopeDigest: scope.scope_digest,
    language: "embedded-web",
    expected,
    force: args.force === "true",
  });
  if (cached) {
    printManifestResult(outputPath, cached, true);
    return;
  }
  const parsedFiles = [];
  const units = [];
  const scriptBlocks = [];
  const diagnostics = [];

  for (const path of expected) {
    try {
      const text = await readFile(resolve(root, path), "utf8");
      parseTemplateUnits(path, text, units, scriptBlocks);
      parsedFiles.push(path);
    } catch (error) {
      diagnostics.push({ path, error: error.message });
    }
  }

  const workDir = resolve(dirname(outputPath), ".embedded-web-work");
  await rm(workDir, { recursive: true, force: true });
  if (scriptBlocks.length > 0) {
    const scriptsRoot = resolve(workDir, "scripts");
    await mkdir(scriptsRoot, { recursive: true });
    const mapping = new Map();
    for (let index = 0; index < scriptBlocks.length; index += 1) {
      const block = scriptBlocks[index];
      const synthetic = `block-${String(index).padStart(5, "0")}${block.extension}`;
      mapping.set(synthetic, block);
      await writeFile(resolve(scriptsRoot, synthetic), `${"\n".repeat(Math.max(0, block.start_line - 1))}${block.code}\n`, "utf8");
    }

    const scriptsDir = dirname(fileURLToPath(import.meta.url));
    const scopeScript = resolve(scriptsDir, "build-scope-manifest.mjs");
    const joernScript = resolve(scriptsDir, "build-joern-function-manifest.mjs");
    const syntheticScope = resolve(workDir, "scope.json");
    const syntheticFunctions = resolve(workDir, "functions.json");
    run(process.execPath, [scopeScript, "--root", scriptsRoot, "--audit-id", args["audit-id"], "--output", syntheticScope, "--mode", "filesystem"]);
    run(process.execPath, [joernScript, "--root", scriptsRoot, "--audit-id", args["audit-id"], "--scope", syntheticScope, "--language", "javascript", "--output", syntheticFunctions]);
    const extracted = JSON.parse(await readFile(syntheticFunctions, "utf8"));
    for (const item of extracted.functions) {
      const block = mapping.get(item.path);
      if (!block) {
        diagnostics.push({ path: item.path, error: "synthetic-script-mapping-missing" });
        continue;
      }
      const identity = ["embedded-js", block.original_path, block.ordinal, item.qualified_name, item.line_start].join("|");
      units.push({
        ...item,
        function_id: stableId(identity),
        language: "embedded-javascript",
        owner_agent: "web-source-auditor",
        path: block.original_path,
        kind: item.name === ":program" ? "embedded-script-program" : item.kind,
        qualified_name: `${block.original_path}::script[${block.ordinal}]::${item.qualified_name}`,
      });
    }
  }

  units.sort((a, b) => a.path.localeCompare(b.path) || a.line_start - b.line_start || a.qualified_name.localeCompare(b.qualified_name));
  const parsedSet = new Set(parsedFiles);
  const missingFiles = expected.filter(path => !parsedSet.has(path));
  const manifest = {
    schema_version: 1,
    audit_id: args["audit-id"],
    language: "embedded-web",
    extractor: { name: "template-block-and-joern", includes: ["inline-javascript-functions", "template-macros", "html-and-framework-event-handlers", "javascript-url-handlers", "jsp-declaration-blocks", "jsp-service-and-expression-blocks"], input_mode: "frozen-template-list-and-scoped-inline-script-projection", cache_version: FUNCTION_MANIFEST_CACHE_VERSION },
    scope_manifest: scopePath,
    scope_digest: scope.scope_digest,
    expected_files: expected,
    parsed_files: parsedFiles.sort(),
    missing_files: missingFiles,
    diagnostics,
    functions: units,
    summary: { expected_files: expected.length, parsed_files: parsedFiles.length, functions: units.length, script_blocks: scriptBlocks.length, diagnostics: diagnostics.length, missing_files: missingFiles.length },
    complete: missingFiles.length === 0 && diagnostics.length === 0,
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
