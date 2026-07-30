#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { attackChainManifestDigest } from "./attack-chain-contract.mjs";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith("--") || value == null) throw new Error(`Invalid argument near ${token ?? "<end>"}`);
    args[token.slice(2)] = value;
  }
  for (const key of ["adjudication", "output"]) if (!args[key]) throw new Error(`Required argument missing: --${key}`);
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const adjudication = JSON.parse(await readFile(resolve(args.adjudication), "utf8"));
  const supported = adjudication.decisions?.filter(decision => ["SUPPORTED_STATIC", "SUPPORTED_RUNTIME"].includes(decision?.state)) ?? [];
  if (supported.length !== 0) throw new Error("Empty attack-chain report is allowed only when adjudication has no supported findings");
  const output = {
    schema_version: 2,
    audit_id: adjudication.audit_id,
    scope_digest: adjudication.scope_digest,
    adjudication_manifest_digest: adjudication.manifest_digest,
    chains: [],
    gaps: [],
    chain_accounting: {
      raw_chain_ids: [],
      accepted_chain_ids: [],
      rejected_chain_ids: [],
    },
  };
  output.manifest_digest = attackChainManifestDigest(output);
  const outputPath = resolve(args.output);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(output, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ output: outputPath, audit_id: output.audit_id, chains: 0 })}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
