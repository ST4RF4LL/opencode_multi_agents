import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export const FUNCTION_MANIFEST_CACHE_VERSION = 2;

export function contentDigest(value) {
  const copy = { ...value };
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

function exactArray(left, right) {
  return Array.isArray(left)
    && left.length === right.length
    && left.every((value, index) => value === right[index]);
}

export async function assertFrozenSources(root, scope, expected) {
  const byPath = new Map((scope.files ?? []).map(file => [file.path, file]));
  let next = 0;
  async function worker() {
    while (next < expected.length) {
      const path = expected[next];
      next += 1;
      const record = byPath.get(path);
      if (!record?.sha256) throw new Error(`Scoped source lacks a frozen digest: ${path}`);
      const bytes = await readFile(resolve(root, path));
      const current = createHash("sha256").update(bytes).digest("hex");
      if (current !== record.sha256) throw new Error(`Scoped source changed after scope freeze: ${path}`);
    }
  }
  await Promise.all(Array.from({ length: Math.min(16, expected.length) }, worker));
}

export async function reusableManifest(outputPath, { auditId, scopeDigest, language, expected, force }) {
  if (force) return null;
  try {
    const manifest = JSON.parse(await readFile(outputPath, "utf8"));
    if (manifest.audit_id !== auditId
      || manifest.scope_digest !== scopeDigest
      || manifest.language !== language
      || manifest.extractor?.cache_version !== FUNCTION_MANIFEST_CACHE_VERSION
      || manifest.manifest_digest !== contentDigest(manifest)
      || !exactArray(manifest.expected_files, expected)) return null;
    return manifest;
  } catch {
    return null;
  }
}

export function printManifestResult(outputPath, manifest, cached) {
  process.stdout.write(`${JSON.stringify({ output: outputPath, ...manifest.summary, complete: manifest.complete, cached })}\n`);
  if (!manifest.complete) process.exitCode = 2;
}
