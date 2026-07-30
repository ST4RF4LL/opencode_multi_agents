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
  for (const key of ["audit-id", "input", "decisions", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
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

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [manifest, resolution] = await Promise.all([
    readFile(resolve(args.input), "utf8").then(JSON.parse),
    readFile(resolve(args.decisions), "utf8").then(JSON.parse),
  ]);
  if (manifest.audit_id !== args["audit-id"] || manifest.manifest_digest !== objectDigest(manifest)) {
    throw new Error("Interface manifest is modified or bound to another audit");
  }
  if (resolution.schema_version !== 1 || resolution.audit_id !== args["audit-id"]
    || resolution.interface_manifest_digest !== manifest.manifest_digest || !Array.isArray(resolution.decisions)) {
    throw new Error("Candidate resolution file is invalid or bound to another interface manifest");
  }

  const interfaces = new Map((manifest.interfaces ?? []).map(item => [item.interface_id, structuredClone(item)]));
  for (const item of interfaces.values()) item.discovery_origin_state ??= item.discovery_state;
  const seen = new Set();
  for (const decision of resolution.decisions) {
    if (seen.has(decision.interface_id)) throw new Error(`Duplicate interface decision: ${decision.interface_id}`);
    seen.add(decision.interface_id);
    const item = interfaces.get(decision.interface_id);
    if (!item) throw new Error(`Unknown interface decision: ${decision.interface_id}`);
    if (item.discovery_state !== "CANDIDATE") throw new Error(`Only CANDIDATE interfaces can be resolved: ${decision.interface_id}`);
    if (!["CONFIRMED", "REJECTED"].includes(decision.state)) throw new Error(`Invalid interface decision state: ${decision.interface_id}`);
    if (typeof decision.reason !== "string" || decision.reason.trim() === ""
      || !Array.isArray(decision.evidence) || decision.evidence.length === 0
      || decision.evidence.some(item => typeof item !== "object" || item == null || Array.isArray(item))) {
      throw new Error(`Interface decision requires a reason and evidence: ${decision.interface_id}`);
    }
    item.discovery_state = decision.state;
    const canonicalDecision = {
      interface_id: decision.interface_id,
      state: decision.state,
      reason: decision.reason,
      evidence: decision.evidence,
    };
    item.resolution = {
      reason: decision.reason,
      evidence: decision.evidence,
      decided_by: resolution.decided_by ?? null,
      decided_at: resolution.decided_at ?? null,
      resolution_digest: digest(JSON.stringify(canonicalDecision)),
    };
    interfaces.set(item.interface_id, item);
  }

  const values = [...interfaces.values()].sort((left, right) => left.interface_id.localeCompare(right.interface_id));
  const output = {
    ...manifest,
    schema_version: 2,
    parent_manifest_digest: manifest.manifest_digest,
    interfaces: values,
    summary: {
      ...manifest.summary,
      interfaces: values.length,
      confirmed_interfaces: values.filter(item => item.discovery_state === "CONFIRMED").length,
      candidate_interfaces: values.filter(item => item.discovery_state === "CANDIDATE").length,
      rejected_interfaces: values.filter(item => item.discovery_state === "REJECTED").length,
    },
    inventory_bounded: manifest.complete === true && values.every(item => item.discovery_state !== "CANDIDATE"),
    claim_boundary: `${manifest.claim_boundary} Candidate decisions are separately evidence-bound and do not alter extractor anchors.`,
  };
  delete output.manifest_digest;
  output.manifest_digest = objectDigest(output);
  const outputPath = resolve(args.output);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(output, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({
    output: outputPath,
    manifest_digest: output.manifest_digest,
    confirmed: output.summary.confirmed_interfaces,
    candidate: output.summary.candidate_interfaces,
    rejected: output.summary.rejected_interfaces,
    inventory_bounded: output.inventory_bounded,
  })}\n`);
  if (!output.inventory_bounded) process.exitCode = 2;
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
