#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyStageHandoffs } from "./stage-agent-contract.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_REGISTRY = resolve(HERE, "../contracts/stage-agent-contracts.json");
const DEFAULT_ROLES = resolve(HERE, "../../../../agent-manifest/roles.json");

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const field of ["audit-id", "scope-digest", "focus-areas", "handoffs-dir", "round", "output"]) {
    if (!args[field]) throw new Error(`Required argument missing: --${field}`);
  }
  return args;
}

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
}

function verificationDigest(value) {
  const copy = structuredClone(value);
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(canonicalize(copy))).digest("hex");
}

async function readJson(path) {
  return JSON.parse(await readFile(resolve(path), "utf8"));
}

async function listOutputEnvelopes(directory) {
  const files = [];
  async function visit(path) {
    let entries;
    try {
      entries = await readdir(path, { withFileTypes: true });
    } catch (error) {
      if (error.code === "ENOENT") return;
      throw error;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) await visit(child);
      else if (entry.isFile() && entry.name.endsWith(".output.json")) files.push(child);
    }
  }
  await visit(resolve(directory));
  return files;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const round = Number(args.round);
  const candidateCount = Number(args["candidate-count"] ?? "0");
  if (!Number.isInteger(round) || round < 1 || !Number.isInteger(candidateCount) || candidateCount < 0) {
    throw new Error("--round and --candidate-count must be non-negative integers, with round >= 1");
  }
  const [registry, roles, focusManifest, outputPaths] = await Promise.all([
    readJson(args.registry ?? DEFAULT_REGISTRY),
    readJson(args.roles ?? DEFAULT_ROLES),
    readJson(args["focus-areas"]),
    listOutputEnvelopes(args["handoffs-dir"]),
  ]);
  if (focusManifest.audit_id !== args["audit-id"] || focusManifest.scope_digest !== args["scope-digest"]) {
    throw new Error("Focus Area manifest is bound to another audit or scope");
  }
  const handoffs = await Promise.all(outputPaths.map(async outputPath => {
    const inputPath = outputPath.slice(0, -".output.json".length) + ".input.json";
    let input;
    try {
      input = await readJson(inputPath);
    } catch (error) {
      input = null;
    }
    return {
      path: outputPath,
      input,
      output: await readJson(outputPath),
    };
  }));
  const result = verifyStageHandoffs({
    registry,
    roles,
    focusManifest,
    handoffs,
    round,
    throughStageId: args["through-stage"] ?? "P08_FINALIZE",
    candidateCount,
  });
  const verification = {
    schema_version: 1,
    audit_id: args["audit-id"],
    scope_digest: args["scope-digest"],
    round,
    through_stage_id: args["through-stage"] ?? "P08_FINALIZE",
    candidate_count: candidateCount,
    inputs: {
      registry: resolve(args.registry ?? DEFAULT_REGISTRY),
      roles: resolve(args.roles ?? DEFAULT_ROLES),
      focus_areas: resolve(args["focus-areas"]),
      handoffs_directory: resolve(args["handoffs-dir"]),
    },
    expected: result.expected,
    observed_complete_output_digests: result.observed_complete_output_digests,
    missing: result.missing,
    invalid: result.invalid,
    complete: result.complete,
    claim_boundary: "Proves that all fixed stages through the requested boundary and every Focus Area assignment/lens plus required discovery track have matching, digest-bound COMPLETE output envelopes. It does not replace structural, semantic, finding-adjudication, or attack-chain evidence validation.",
  };
  verification.manifest_digest = verificationDigest(verification);
  const output = resolve(args.output);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(verification, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({
    output,
    complete: verification.complete,
    expected: verification.expected.length,
    observed: verification.observed_complete_output_digests.length,
    missing: verification.missing.length,
    invalid: verification.invalid.length,
  })}\n`);
  if (!verification.complete) process.exitCode = 2;
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
