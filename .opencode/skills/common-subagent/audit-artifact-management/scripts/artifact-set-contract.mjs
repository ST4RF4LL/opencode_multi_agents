import { createHash } from "node:crypto";

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
}

function exactKeys(value, expected) {
  return isObject(value) && Object.keys(value).length === expected.length
    && expected.every(key => Object.hasOwn(value, key));
}

function validAuditId(value) {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/.test(value);
}

function validDigest(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function validReportsPath(value) {
  return typeof value === "string" && value.startsWith("reports/") && !value.includes("\\")
    && !value.includes("\0") && !value.split("/").includes("..");
}

export function artifactSetDigest(value) {
  const copy = structuredClone(value);
  delete copy.set_digest;
  return createHash("sha256").update(JSON.stringify(canonicalize(copy))).digest("hex");
}

export function validateArtifactSetIndex(index, {
  expectedSetType = null,
  auditId = null,
  round = null,
  scopeDigest = null,
} = {}) {
  const errors = [];
  if (!exactKeys(index, ["schema_version", "set_type", "audit_id", "round", "scope_digest", "items", "item_count", "set_digest"])) {
    return ["artifact-set-fields-not-exact"];
  }
  if (index.schema_version !== 1) errors.push("artifact-set-schema-version-invalid");
  if (typeof index.set_type !== "string" || index.set_type.length === 0
    || (expectedSetType !== null && index.set_type !== expectedSetType)) errors.push("artifact-set-type-invalid");
  if (!validAuditId(index.audit_id) || (auditId !== null && index.audit_id !== auditId)) errors.push("artifact-set-audit-id-invalid");
  if (!Number.isInteger(index.round) || index.round < 1 || (round !== null && index.round !== round)) errors.push("artifact-set-round-invalid");
  if (!validDigest(index.scope_digest) || (scopeDigest !== null && index.scope_digest !== scopeDigest)) errors.push("artifact-set-scope-digest-invalid");
  if (!Array.isArray(index.items)) {
    errors.push("artifact-set-items-invalid");
  } else {
    const identities = new Set();
    for (const [itemIndex, item] of index.items.entries()) {
      const prefix = `artifact-set-item:${itemIndex}`;
      if (!exactKeys(item, ["artifact_type", "path", "sha256", "media_type", "json_pointer"])) {
        errors.push(`${prefix}:fields-not-exact`);
        continue;
      }
      if (typeof item.artifact_type !== "string" || item.artifact_type.length === 0) errors.push(`${prefix}:artifact-type-invalid`);
      if (!validReportsPath(item.path)) errors.push(`${prefix}:path-invalid`);
      if (!validDigest(item.sha256)) errors.push(`${prefix}:sha256-invalid`);
      if (typeof item.media_type !== "string" || item.media_type.length === 0) errors.push(`${prefix}:media-type-invalid`);
      if (!(item.json_pointer === null || (typeof item.json_pointer === "string" && item.json_pointer.startsWith("/")))) {
        errors.push(`${prefix}:json-pointer-invalid`);
      }
      const identity = `${item.artifact_type}\0${item.path}\0${item.json_pointer ?? ""}`;
      if (identities.has(identity)) errors.push(`${prefix}:duplicate`);
      identities.add(identity);
    }
  }
  if (!Number.isInteger(index.item_count) || index.item_count < 0 || index.item_count !== index.items?.length) {
    errors.push("artifact-set-item-count-invalid");
  }
  if (!validDigest(index.set_digest) || index.set_digest !== artifactSetDigest(index)) errors.push("artifact-set-digest-invalid");
  return [...new Set(errors)];
}
