#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, extname, posix, resolve } from "node:path";

const SCHEMA_VERSION = 1;
const EXTRACTOR_VERSION = 1;
const LENSES = ["sink-driven", "control-driven", "config-driven"];
const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "trace"]);

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["root", "audit-id", "scope", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function objectDigest(value) {
  const copy = { ...value };
  delete copy.manifest_digest;
  return digest(JSON.stringify(copy));
}

function stableId(value) {
  return `interface:${digest(value).slice(0, 24)}`;
}

function lineAt(text, offset) {
  let line = 1;
  for (let index = 0; index < offset; index += 1) if (text.charCodeAt(index) === 10) line += 1;
  return line;
}

function normalizeAddress(value) {
  return String(value ?? "").trim().replace(/\s+/g, " ");
}

function dimensionsFor(kind, direction) {
  if (kind === "scheduler") return ["D3", "D8", "D9"];
  if (kind === "cli") return ["D1", "D2", "D3", "D8", "D9"];
  if (kind === "mcp-tool") return ["D1", "D2", "D3", "D4", "D6", "D8", "D9"];
  if (kind.startsWith("message-")) return ["D1", "D2", "D3", "D4", "D8", "D9"];
  if (kind === "outbound-network" || direction === "egress") return ["D1", "D3", "D6", "D8", "D9"];
  if (kind === "configured-network") return ["D2", "D3", "D6", "D8"];
  return ["D1", "D2", "D3", "D8", "D9"];
}

function scannerFor(file, scopePaths) {
  const extension = extname(file.path.toLowerCase());
  if (file.type === "symlink") {
    const target = posix.normalize(posix.join(posix.dirname(file.path), file.link_target ?? ""));
    return scopePaths.has(target)
      ? { state: "NOT_APPLICABLE", extractor_ids: [], reason: "symlink-interface-content-covered-by-scoped-target" }
      : { state: "INDETERMINATE", extractor_ids: [], reason: "symlink-target-not-covered-by-frozen-scope" };
  }
  if (file.content_kind === "binary") return { state: "NOT_APPLICABLE", extractor_ids: [], reason: "binary-artifact" };
  if ([".java", ".kt", ".kts"].includes(extension)) return { state: "INSPECTED", extractor_ids: ["jvm-interface-anchors"], reason: "supported-jvm-source" };
  if ([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"].includes(extension)) return { state: "INSPECTED", extractor_ids: ["javascript-interface-anchors"], reason: "supported-javascript-source" };
  if ([".py", ".pyw"].includes(extension)) return { state: "INSPECTED", extractor_ids: ["python-interface-anchors"], reason: "supported-python-source" };
  if ([".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"].includes(extension)) return { state: "INSPECTED", extractor_ids: ["native-interface-anchors"], reason: "supported-native-source" };
  if ([".html", ".htm", ".jsp", ".jspx", ".vue", ".svelte", ".hbs", ".mustache", ".ftl", ".ftlh"].includes(extension)) {
    return { state: "INSPECTED", extractor_ids: ["web-template-interface-anchors"], reason: "supported-web-template" };
  }
  if ([".proto", ".graphql", ".gql", ".wsdl"].includes(extension)) return { state: "INSPECTED", extractor_ids: ["declarative-interface-spec"], reason: "supported-interface-spec" };
  if (file.content_kind === "configuration" || ["dockerfile", "procfile"].includes(file.path.toLowerCase().split("/").at(-1))) {
    return { state: "INSPECTED", extractor_ids: ["configuration-interface-anchors"], reason: "supported-configuration" };
  }
  if (file.function_inventory_state === "unsupported" || file.content_kind === "unknown-text") {
    return { state: "INDETERMINATE", extractor_ids: [], reason: "potential-interface-source-without-configured-extractor" };
  }
  return { state: "NOT_APPLICABLE", extractor_ids: [], reason: "known-non-interface-artifact" };
}

function scanMatches(text, regex, callback) {
  regex.lastIndex = 0;
  let match;
  while ((match = regex.exec(text)) !== null) {
    callback(match);
    if (match[0].length === 0) regex.lastIndex += 1;
  }
}

function scanJvm(text, emit, gap) {
  scanMatches(text, /@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(([^)]*)\)/g, match => {
    const literals = [...match[2].matchAll(/["']([^"']+)["']/g)].map(item => item[1]);
    const method = match[1] === "Request"
      ? /RequestMethod\.([A-Z]+)/.exec(match[2])?.[1] ?? "ANY"
      : match[1].toUpperCase();
    if (literals.length === 0) {
      gap("dynamic-jvm-route", match.index, match[0]);
      return;
    }
    for (const address of literals) emit({ extractor_id: "jvm-interface-anchors", direction: "ingress", kind: "http", protocol: "http", operation: method, address, state: "CANDIDATE", offset: match.index, matched: match[0] });
  });
  const annotations = [
    ["KafkaListener", "message-consumer", "kafka"],
    ["RabbitListener", "message-consumer", "amqp"],
    ["JmsListener", "message-consumer", "jms"],
    ["Scheduled", "scheduler", "scheduler"],
    ["ShellMethod", "cli", "cli"],
  ];
  for (const [annotation, kind, protocol] of annotations) {
    const regex = new RegExp(`@${annotation}\\\\s*\\\\(([^)]*)\\\\)`, "g");
    scanMatches(text, regex, match => {
      const address = /["']([^"']+)["']/.exec(match[1])?.[1] ?? `<${annotation}>`;
      emit({ extractor_id: "jvm-interface-anchors", direction: "ingress", kind, protocol, operation: annotation, address, state: "CANDIDATE", offset: match.index, matched: match[0] });
    });
  }
  scanMatches(text, /\b(?:fetch|exchange|execute)\s*\(\s*([^,\n)]+)/g, match => {
    emit({ extractor_id: "jvm-interface-anchors", direction: "egress", kind: "outbound-network", protocol: "http-or-custom", operation: "CALL", address: stringLiteral(match[1]) ?? "<dynamic>", state: "CANDIDATE", offset: match.index, matched: match[0] });
  });
}

function stringLiteral(value) {
  return /^\s*["'`]([^"'`]*)["'`]\s*$/.exec(value)?.[1] ?? null;
}

function scanJavascript(text, emit, gap) {
  scanMatches(text, /\b(app|router|server|fastify)\s*\.\s*(get|post|put|patch|delete|options|head|all)\s*\(\s*([^,\n)]+)/gi, match => {
    const address = stringLiteral(match[3]);
    if (address == null) {
      gap("dynamic-javascript-route", match.index, match[0]);
      return;
    }
    emit({ extractor_id: "javascript-interface-anchors", direction: "ingress", kind: "http", protocol: "http", operation: match[2].toUpperCase(), address, state: "CONFIRMED", offset: match.index, matched: match[0] });
  });
  scanMatches(text, /\b(?:server|mcpServer)\s*\.\s*(?:tool|registerTool)\s*\(\s*([^,\n)]+)/g, match => {
    const address = stringLiteral(match[1]);
    if (address == null) gap("dynamic-mcp-tool-name", match.index, match[0]);
    else emit({ extractor_id: "javascript-interface-anchors", direction: "bidirectional", kind: "mcp-tool", protocol: "mcp", operation: "TOOL", address, state: "CONFIRMED", offset: match.index, matched: match[0] });
  });
  scanMatches(text, /\b(?:program|yargs)\s*\.\s*command\s*\(\s*([^,\n)]+)/g, match => {
    const address = stringLiteral(match[1]);
    if (address != null) emit({ extractor_id: "javascript-interface-anchors", direction: "ingress", kind: "cli", protocol: "cli", operation: "COMMAND", address, state: "CONFIRMED", offset: match.index, matched: match[0] });
  });
  scanMatches(text, /\b(?:cron|schedule)\s*\.\s*(?:schedule|job)\s*\(\s*([^,\n)]+)/g, match => {
    emit({ extractor_id: "javascript-interface-anchors", direction: "ingress", kind: "scheduler", protocol: "scheduler", operation: "TRIGGER", address: stringLiteral(match[1]) ?? "<dynamic-schedule>", state: "CANDIDATE", offset: match.index, matched: match[0] });
  });
  scanMatches(text, /\b(?:fetch|axios\.(?:get|post|put|patch|delete)|axios|got|request)\s*\(\s*([^,\n)]+)/g, match => {
    emit({ extractor_id: "javascript-interface-anchors", direction: "egress", kind: "outbound-network", protocol: "http", operation: "CALL", address: stringLiteral(match[1]) ?? "<dynamic>", state: "CANDIDATE", offset: match.index, matched: match[0] });
  });
}

function scanPython(text, emit, gap) {
  scanMatches(text, /@(?:app|router|blueprint)\s*\.\s*(get|post|put|patch|delete|route)\s*\(\s*([^,\n)]+)/g, match => {
    const address = stringLiteral(match[2]);
    if (address == null) {
      gap("dynamic-python-route", match.index, match[0]);
      return;
    }
    emit({ extractor_id: "python-interface-anchors", direction: "ingress", kind: "http", protocol: "http", operation: match[1] === "route" ? "ANY" : match[1].toUpperCase(), address, state: "CONFIRMED", offset: match.index, matched: match[0] });
  });
  scanMatches(text, /@(?:mcp|server)\s*\.\s*tool\s*\(\s*(?:name\s*=\s*)?([^,\n)]*)/g, match => {
    const address = stringLiteral(match[1]) ?? "<decorated-function-name>";
    emit({ extractor_id: "python-interface-anchors", direction: "bidirectional", kind: "mcp-tool", protocol: "mcp", operation: "TOOL", address, state: address.startsWith("<") ? "CANDIDATE" : "CONFIRMED", offset: match.index, matched: match[0] });
  });
  scanMatches(text, /@(?:shared_task|app\.task|celery\.task|click\.command)\b(?:\s*\(([^)]*)\))?/g, match => {
    const cli = match[0].includes("click.command");
    emit({ extractor_id: "python-interface-anchors", direction: "ingress", kind: cli ? "cli" : "message-consumer", protocol: cli ? "cli" : "celery", operation: cli ? "COMMAND" : "TASK", address: /["']([^"']+)["']/.exec(match[1] ?? "")?.[1] ?? "<decorated-function-name>", state: "CANDIDATE", offset: match.index, matched: match[0] });
  });
  scanMatches(text, /\b(?:requests|httpx)\s*\.\s*(get|post|put|patch|delete|request)\s*\(\s*([^,\n)]+)/g, match => {
    emit({ extractor_id: "python-interface-anchors", direction: "egress", kind: "outbound-network", protocol: "http", operation: match[1].toUpperCase(), address: stringLiteral(match[2]) ?? "<dynamic>", state: "CANDIDATE", offset: match.index, matched: match[0] });
  });
}

function scanNative(text, emit) {
  const calls = [
    ["bind", "ingress", "socket", "BIND"],
    ["listen", "ingress", "socket", "LISTEN"],
    ["accept", "ingress", "socket", "ACCEPT"],
    ["connect", "egress", "outbound-network", "CONNECT"],
    ["curl_easy_perform", "egress", "outbound-network", "HTTP_CALL"],
  ];
  for (const [name, direction, kind, operation] of calls) {
    const regex = new RegExp(`\\\\b${name}\\\\s*\\\\(`, "g");
    scanMatches(text, regex, match => emit({ extractor_id: "native-interface-anchors", direction, kind, protocol: kind === "socket" ? "socket" : "http-or-custom", operation, address: "<resolved-at-runtime>", state: "CANDIDATE", offset: match.index, matched: match[0] }));
  }
}

function scanTemplate(text, emit) {
  scanMatches(text, /<(?:form|a)\b[^>]*\b(?:action|href)\s*=\s*["']([^"']+)["'][^>]*>/gi, match => {
    if (/^(?:#|javascript:)/i.test(match[1])) return;
    emit({ extractor_id: "web-template-interface-anchors", direction: "egress", kind: "browser-navigation", protocol: "http", operation: match[0].toLowerCase().startsWith("<form") ? "FORM" : "NAVIGATE", address: match[1], state: "CANDIDATE", offset: match.index, matched: match[0] });
  });
  scanMatches(text, /\bfetch\s*\(\s*([^,\n)]+)/g, match => emit({ extractor_id: "web-template-interface-anchors", direction: "egress", kind: "outbound-network", protocol: "http", operation: "CALL", address: stringLiteral(match[1]) ?? "<dynamic>", state: "CANDIDATE", offset: match.index, matched: match[0] }));
}

function scanSpec(path, text, emit, gap) {
  const extension = extname(path.toLowerCase());
  if (extension === ".proto") {
    scanMatches(text, /\brpc\s+([A-Za-z_]\w*)\s*\(/g, match => emit({ extractor_id: "declarative-interface-spec", direction: "ingress", kind: "rpc", protocol: "grpc", operation: "RPC", address: match[1], state: "CONFIRMED", offset: match.index, matched: match[0] }));
    return;
  }
  if ([".graphql", ".gql"].includes(extension)) {
    scanMatches(text, /\btype\s+(Query|Mutation|Subscription)\s*\{([\s\S]*?)\}/g, block => {
      scanMatches(block[2], /^\s*([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*:/gm, field => emit({ extractor_id: "declarative-interface-spec", direction: "ingress", kind: "graphql", protocol: "graphql", operation: block[1].toUpperCase(), address: field[1], state: "CONFIRMED", offset: block.index + field.index, matched: field[0] }));
    });
    return;
  }
  if (extension === ".wsdl") {
    scanMatches(text, /<(?:\w+:)?operation\b[^>]*\bname=["']([^"']+)["']/g, match => emit({ extractor_id: "declarative-interface-spec", direction: "ingress", kind: "rpc", protocol: "soap", operation: "OPERATION", address: match[1], state: "CONFIRMED", offset: match.index, matched: match[0] }));
    return;
  }
  gap("unsupported-declarative-interface-spec", 0, path);
}

function scanConfiguration(path, text, emit, gap) {
  let parsedJson = null;
  if (path.toLowerCase().endsWith(".json")) {
    try {
      parsedJson = JSON.parse(text);
    } catch {
      parsedJson = null;
    }
  }
  if (parsedJson && (parsedJson.openapi || parsedJson.swagger) && parsedJson.paths && typeof parsedJson.paths === "object") {
    for (const [address, pathItem] of Object.entries(parsedJson.paths)) {
      const methods = Object.keys(pathItem ?? {}).filter(key => HTTP_METHODS.has(key.toLowerCase()));
      if (methods.length === 0) gap("openapi-path-without-operation", text.indexOf(`"${address}"`), address);
      for (const method of methods) emit({ extractor_id: "configuration-interface-anchors", direction: "ingress", kind: "http", protocol: "openapi", operation: method.toUpperCase(), address, state: "CONFIRMED", offset: Math.max(0, text.indexOf(`"${address}"`)), matched: `${method} ${address}` });
    }
    return;
  }
  if (/^\s*(?:openapi|swagger)\s*:/m.test(text) && /^\s*paths\s*:/m.test(text)) {
    const lines = text.split(/\r?\n/);
    let inPaths = false;
    let pathsIndent = -1;
    let currentPath = null;
    let pathIndent = -1;
    let offset = 0;
    for (const line of lines) {
      const indent = /^\s*/.exec(line)[0].length;
      if (!inPaths && /^\s*paths\s*:/.test(line)) {
        inPaths = true;
        pathsIndent = indent;
      } else if (inPaths && line.trim() && indent <= pathsIndent) {
        inPaths = false;
      } else if (inPaths) {
        const pathMatch = /^\s*(["']?)(\/[^:"']*)\1\s*:/.exec(line);
        if (pathMatch) {
          currentPath = pathMatch[2];
          pathIndent = indent;
        } else if (currentPath && indent > pathIndent) {
          const methodMatch = /^\s*(get|post|put|patch|delete|options|head|trace)\s*:/.exec(line);
          if (methodMatch) emit({ extractor_id: "configuration-interface-anchors", direction: "ingress", kind: "http", protocol: "openapi", operation: methodMatch[1].toUpperCase(), address: currentPath, state: "CONFIRMED", offset, matched: line });
        }
      }
      offset += line.length + 1;
    }
    return;
  }
  const patterns = [
    [/\bEXPOSE\s+([^\r\n#]+)/g, "LISTEN", "container", "configured-network"],
    [/^\s*listen\s+([^;#\r\n]+)/gm, "LISTEN", "http-or-tcp", "configured-network"],
    [/^\s*server\.port\s*[:=]\s*([^\s#]+)/gm, "LISTEN", "http", "configured-network"],
    [/^\s*-\s*["']?(\d{2,5}(?::\d{2,5})?(?:\/(?:tcp|udp))?)["']?\s*$/gm, "PUBLISH", "container-or-service", "configured-network"],
  ];
  for (const [regex, operation, protocol, kind] of patterns) {
    scanMatches(text, regex, match => emit({ extractor_id: "configuration-interface-anchors", direction: "ingress", kind, protocol, operation, address: match[1], state: "CANDIDATE", offset: match.index, matched: match[0] }));
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = resolve(args.root);
  const scopePath = resolve(args.scope);
  const outputPath = resolve(args.output);
  const scope = JSON.parse(await readFile(scopePath, "utf8"));
  if (scope.audit_id !== args["audit-id"] || !scope.complete || scope.manifest_digest !== objectDigest(scope)) {
    throw new Error("Scope manifest is incomplete, modified, or bound to another audit");
  }

  const interfaces = [];
  const fileCoverage = [];
  const gaps = [];
  const seenKeys = new Set();
  const scopePaths = new Set((scope.files ?? []).map(file => file.path));
  for (const file of scope.files ?? []) {
    if (!file.review_required) continue;
    const selection = scannerFor(file, scopePaths);
    const row = {
      file_id: file.file_id,
      path: file.path,
      source_sha256: file.sha256 ?? null,
      state: selection.state,
      extractor_ids: selection.extractor_ids,
      interface_ids: [],
      reason: selection.reason,
      gaps: [],
    };
    if (selection.state === "INDETERMINATE") {
      row.gaps.push({ code: "INTERFACE_EXTRACTOR_INDETERMINATE", reason: selection.reason });
      gaps.push({ file_id: file.file_id, path: file.path, code: "INTERFACE_EXTRACTOR_INDETERMINATE", reason: selection.reason });
      fileCoverage.push(row);
      continue;
    }
    if (selection.state === "NOT_APPLICABLE") {
      fileCoverage.push(row);
      continue;
    }

    let text;
    try {
      const bytes = await readFile(resolve(root, file.path));
      const sourceDigest = digest(bytes);
      if (sourceDigest !== file.sha256) throw new Error("source-digest-mismatch");
      text = bytes.toString("utf8");
    } catch (error) {
      row.state = "FAILED";
      row.reason = error.message;
      row.gaps.push({ code: "INTERFACE_EXTRACTOR_FAILED", reason: error.message });
      gaps.push({ file_id: file.file_id, path: file.path, code: "INTERFACE_EXTRACTOR_FAILED", reason: error.message });
      fileCoverage.push(row);
      continue;
    }

    const emit = item => {
      const address = normalizeAddress(item.address);
      const lineStart = lineAt(text, item.offset);
      const key = [file.path, lineStart, item.extractor_id, item.direction, item.kind, item.protocol, item.operation, address].join("\n");
      if (seenKeys.has(key)) return;
      seenKeys.add(key);
      const interfaceId = stableId(key);
      interfaces.push({
        interface_id: interfaceId,
        discovery_state: item.state,
        direction: item.direction,
        kind: item.kind,
        protocol: item.protocol,
        operation: item.operation,
        address,
        file_id: file.file_id,
        path: file.path,
        owner_agent: file.owner_agent,
        line_start: lineStart,
        dimensions: dimensionsFor(item.kind, item.direction),
        required_lenses: LENSES,
        evidence: [{
          kind: "interface-source-anchor",
          extractor_id: item.extractor_id,
          file_id: file.file_id,
          path: file.path,
          source_sha256: file.sha256,
          line_start: lineStart,
          match_sha256: digest(item.matched),
        }],
      });
      row.interface_ids.push(interfaceId);
    };
    const gap = (code, offset, matched) => {
      const item = { code, line_start: lineAt(text, Math.max(0, offset)), match_sha256: digest(matched) };
      row.gaps.push(item);
      gaps.push({ file_id: file.file_id, path: file.path, ...item });
      row.state = "INDETERMINATE";
      row.reason = "dynamic-or-unsupported-interface-registration";
    };

    const extractor = selection.extractor_ids[0];
    if (extractor === "jvm-interface-anchors") scanJvm(text, emit, gap);
    else if (extractor === "javascript-interface-anchors") scanJavascript(text, emit, gap);
    else if (extractor === "python-interface-anchors") scanPython(text, emit, gap);
    else if (extractor === "native-interface-anchors") scanNative(text, emit);
    else if (extractor === "web-template-interface-anchors") scanTemplate(text, emit);
    else if (extractor === "declarative-interface-spec") scanSpec(file.path, text, emit, gap);
    else if (extractor === "configuration-interface-anchors") scanConfiguration(file.path, text, emit, gap);
    row.interface_ids.sort();
    fileCoverage.push(row);
  }

  interfaces.sort((left, right) => left.interface_id.localeCompare(right.interface_id));
  fileCoverage.sort((left, right) => left.file_id.localeCompare(right.file_id));
  gaps.sort((left, right) => `${left.path}:${left.line_start ?? 0}:${left.code}`.localeCompare(`${right.path}:${right.line_start ?? 0}:${right.code}`));
  const manifest = {
    schema_version: SCHEMA_VERSION,
    extractor_version: EXTRACTOR_VERSION,
    audit_id: args["audit-id"],
    scope_digest: scope.scope_digest,
    required_lenses: LENSES,
    extractor_ids: [
      "configuration-interface-anchors",
      "declarative-interface-spec",
      "javascript-interface-anchors",
      "jvm-interface-anchors",
      "native-interface-anchors",
      "python-interface-anchors",
      "web-template-interface-anchors",
    ],
    interfaces,
    file_coverage: fileCoverage,
    gaps,
    summary: {
      scoped_files: (scope.files ?? []).filter(file => file.review_required).length,
      inspected_files: fileCoverage.filter(item => item.state === "INSPECTED").length,
      not_applicable_files: fileCoverage.filter(item => item.state === "NOT_APPLICABLE").length,
      indeterminate_files: fileCoverage.filter(item => item.state === "INDETERMINATE").length,
      failed_files: fileCoverage.filter(item => item.state === "FAILED").length,
      interfaces: interfaces.length,
      confirmed_interfaces: interfaces.filter(item => item.discovery_state === "CONFIRMED").length,
      candidate_interfaces: interfaces.filter(item => item.discovery_state === "CANDIDATE").length,
      ingress: interfaces.filter(item => item.direction === "ingress").length,
      egress: interfaces.filter(item => item.direction === "egress").length,
      bidirectional: interfaces.filter(item => item.direction === "bidirectional").length,
    },
    complete: gaps.length === 0,
    claim_boundary: "Enumerates deterministic source/spec/config interface anchors recognized by the configured extractors. CONFIRMED means a literal framework/spec declaration; CANDIDATE means a reviewable executable or configuration anchor. Dynamic registration, unsupported potential sources, symlinks, and extractor failures remain explicit gaps and prohibit complete interface-inventory claims.",
  };
  manifest.manifest_digest = objectDigest(manifest);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: outputPath, complete: manifest.complete, ...manifest.summary, gaps: gaps.length, manifest_digest: manifest.manifest_digest })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
