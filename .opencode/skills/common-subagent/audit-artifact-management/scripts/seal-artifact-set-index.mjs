#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { readFile, rename, writeFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { artifactSetDigest, validateArtifactSetIndex } from "./artifact-set-contract.mjs";

const workspaceRoot = resolve(process.env.AUDIT_WORKSPACE_ROOT ?? process.cwd());
const candidate = process.argv[2]
  ? (isAbsolute(process.argv[2]) ? resolve(process.argv[2]) : resolve(workspaceRoot, process.argv[2]))
  : null;
const relativePath = candidate ? relative(workspaceRoot, candidate).split(sep).join("/") : null;
const path = relativePath?.startsWith("reports/") && !relativePath.split("/").includes("..") ? candidate : null;
if (!process.argv[2]) {
  process.stderr.write("用法：seal-artifact-set-index.mjs <set-index.json>\n");
  process.exitCode = 2;
} else if (!path) {
  process.stderr.write("集合索引必须位于受控 reports/ 下。\n");
  process.exitCode = 2;
} else {
  try {
    const value = JSON.parse(await readFile(path, "utf8"));
    if (!Array.isArray(value.items)) throw new Error("集合索引缺少 items。");
    value.item_count = value.items.length;
    value.set_digest = artifactSetDigest(value);
    const errors = validateArtifactSetIndex(value);
    if (errors.length > 0) throw new Error(`集合索引无效：${errors.join(", ")}`);
    const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, path);
    process.stdout.write(`${JSON.stringify({ complete: true, item_count: value.item_count, set_digest: value.set_digest })}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
