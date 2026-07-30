#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["audit-id", "input", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function objectDigest(value) {
  const copy = structuredClone(value);
  delete copy.manifest_digest;
  return digest(JSON.stringify(copy));
}

function sourceAnchorValid(anchor) {
  return anchor && typeof anchor === "object"
    && anchor.kind === "interface-source-anchor"
    && typeof anchor.extractor_id === "string" && anchor.extractor_id.length > 0
    && typeof anchor.path === "string" && anchor.path.length > 0
    && Number.isInteger(anchor.line_start) && anchor.line_start > 0
    && typeof anchor.match_sha256 === "string" && /^[a-f0-9]{64}$/.test(anchor.match_sha256);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const inputPath = resolve(args.input);
  const manifest = JSON.parse(await readFile(inputPath, "utf8"));
  if (manifest.audit_id !== args["audit-id"] || manifest.manifest_digest !== objectDigest(manifest)) {
    throw new Error("Interface manifest is modified or bound to another audit");
  }
  if (!manifest.complete || !Array.isArray(manifest.interfaces)) {
    throw new Error("Source-anchored resolution requires a gap-free raw interface manifest");
  }
  const decisions = [];
  for (const item of manifest.interfaces) {
    if (item?.discovery_state !== "CANDIDATE") continue;
    const anchors = (item.evidence ?? []).filter(sourceAnchorValid);
    if (anchors.length !== 1) throw new Error(`Candidate ${item?.interface_id ?? "unknown"} does not have exactly one source anchor`);
    const anchor = anchors[0];
    decisions.push({
      interface_id: item.interface_id,
      state: "CONFIRMED",
      reason: `Literal ${item.kind}/${item.operation} declaration confirmed by ${anchor.extractor_id}; semantics beyond interface existence remain subject to coverage review.`,
      evidence: [{
        kind: anchor.kind,
        extractor_id: anchor.extractor_id,
        path: anchor.path,
        line_start: anchor.line_start,
        match_sha256: anchor.match_sha256,
      }],
    });
  }
  const output = {
    schema_version: 1,
    audit_id: args["audit-id"],
    interface_manifest_digest: manifest.manifest_digest,
    decided_by: "deterministic-source-anchor-resolver",
    decisions: decisions.sort((left, right) => left.interface_id.localeCompare(right.interface_id)),
  };
  const outputPath = resolve(args.output);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(output, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: outputPath, candidates_confirmed: decisions.length, input_manifest_digest: manifest.manifest_digest })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
