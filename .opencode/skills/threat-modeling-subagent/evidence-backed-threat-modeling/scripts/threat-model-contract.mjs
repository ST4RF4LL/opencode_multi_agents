import { createHash } from "node:crypto";

export const THREAT_MODEL_SCHEMA_VERSION = 1;
export const THREAT_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const MODES = new Set(["bootstrap", "bootstrap-then-interview", "refine"]);
const ASSUMPTION_CATEGORIES = new Set([
  "architecture",
  "deployment",
  "identity",
  "data",
  "dependency",
  "operator",
  "external",
]);
const ASSUMPTION_STATES = new Set(["VERIFIED", "UNVERIFIED", "CONTRADICTED"]);

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function validDigest(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function uniqueStrings(value, { required = false } = {}) {
  return Array.isArray(value)
    && (!required || value.length > 0)
    && value.every(nonEmptyString)
    && new Set(value).size === value.length;
}

function nonEmptyEvidence(value) {
  return Array.isArray(value) && value.length > 0 && value.every(item => {
    if (typeof item === "string") return item.trim().length > 0;
    return isObject(item) && Object.keys(item).length > 0;
  });
}

function idMap(value, idField, label, errors) {
  if (!Array.isArray(value)) {
    errors.push(`${label}-missing`);
    return new Map();
  }
  const map = new Map();
  for (const [index, item] of value.entries()) {
    const id = item?.[idField];
    if (!isObject(item) || !nonEmptyString(id)) errors.push(`${label}-${index}-invalid`);
    else if (map.has(id)) errors.push(`${label}-id-duplicate`);
    else map.set(id, item);
  }
  return map;
}

function refsValid(value, map, { required = false } = {}) {
  return uniqueStrings(value, { required }) && value.every(id => map.has(id));
}

export function threatModelDigest(model) {
  const copy = structuredClone(model);
  delete copy.manifest_digest;
  return createHash("sha256").update(JSON.stringify(copy)).digest("hex");
}

export function validateThreatModel(model, context = {}) {
  const errors = [];
  if (!isObject(model)) return ["threat-model-not-object"];
  if (model.schema_version !== THREAT_MODEL_SCHEMA_VERSION) errors.push("threat-model-schema-version-invalid");
  if (!nonEmptyString(model.audit_id)) errors.push("threat-model-audit-id-missing");
  if (!validDigest(model.scope_digest)) errors.push("threat-model-scope-digest-invalid");
  if (context.auditId && model.audit_id !== context.auditId) errors.push("threat-model-audit-id-mismatch");
  if (context.scopeDigest && model.scope_digest !== context.scopeDigest) errors.push("threat-model-scope-digest-mismatch");
  if (!MODES.has(model.mode)) errors.push("threat-model-mode-invalid");
  if (!nonEmptyString(model.system_context)) errors.push("threat-model-system-context-missing");

  const assets = idMap(model.assets, "asset_id", "assets", errors);
  const actors = idMap(model.actors, "actor_id", "actors", errors);
  const boundaries = idMap(model.trust_boundaries, "trust_boundary_id", "trust-boundaries", errors);
  const entryPoints = idMap(model.entry_points, "entry_point_id", "entry-points", errors);
  const threats = idMap(model.threats, "threat_id", "threats", errors);

  for (const [id, asset] of assets) {
    if (!nonEmptyString(asset.name) || !nonEmptyString(asset.sensitivity) || !nonEmptyEvidence(asset.evidence)) {
      errors.push(`asset:${id}:invalid`);
    }
  }
  for (const [id, actor] of actors) {
    if (!nonEmptyString(actor.type) || !uniqueStrings(actor.capabilities) || !nonEmptyEvidence(actor.evidence)) {
      errors.push(`actor:${id}:invalid`);
    }
  }
  for (const [id, boundary] of boundaries) {
    if (!nonEmptyString(boundary.from) || !nonEmptyString(boundary.to) || !nonEmptyEvidence(boundary.evidence)) {
      errors.push(`trust-boundary:${id}:invalid`);
    }
  }
  for (const [id, entryPoint] of entryPoints) {
    if (!nonEmptyString(entryPoint.name)
      || !refsValid(entryPoint.trust_boundary_ids, boundaries)
      || !refsValid(entryPoint.reachable_asset_ids, assets, { required: true })
      || !uniqueStrings(entryPoint.inventory_ids)
      || !nonEmptyEvidence(entryPoint.evidence)) {
      errors.push(`entry-point:${id}:invalid`);
    }
  }
  for (const [id, threat] of threats) {
    if (!nonEmptyString(threat.outcome)
      || !refsValid(threat.actor_ids, actors, { required: true })
      || !refsValid(threat.entry_point_ids, entryPoints, { required: true })
      || !refsValid(threat.trust_boundary_ids, boundaries)
      || !refsValid(threat.asset_ids, assets, { required: true })
      || !uniqueStrings(threat.dimensions, { required: true })
      || !nonEmptyString(threat.impact)
      || !nonEmptyString(threat.likelihood)
      || !nonEmptyString(threat.status)
      || !Array.isArray(threat.controls)
      || !nonEmptyEvidence(threat.evidence)
      || !uniqueStrings(threat.provenance_tags, { required: true })) {
      errors.push(`threat:${id}:invalid`);
    }
  }

  const invariants = idMap(model.security_invariants, "invariant_id", "security-invariants", errors);
  if (assets.size > 0 && invariants.size === 0) errors.push("security-invariants-empty");
  for (const [id, invariant] of invariants) {
    if (!nonEmptyString(invariant.statement)
      || !refsValid(invariant.asset_ids, assets, { required: true })
      || !refsValid(invariant.threat_ids, threats)
      || !uniqueStrings(invariant.enforcement_points)
      || !nonEmptyEvidence(invariant.evidence)
      || !uniqueStrings(invariant.provenance_tags, { required: true })) {
      errors.push(`security-invariant:${id}:invalid`);
    }
  }

  const assumptions = idMap(model.assumptions, "assumption_id", "assumptions", errors);
  for (const [id, assumption] of assumptions) {
    const evidenceRequired = assumption.status !== "UNVERIFIED";
    if (!nonEmptyString(assumption.statement)
      || !ASSUMPTION_CATEGORIES.has(assumption.category)
      || !ASSUMPTION_STATES.has(assumption.status)
      || !refsValid(assumption.affects_threat_ids, threats)
      || !Array.isArray(assumption.evidence)
      || (evidenceRequired && !nonEmptyEvidence(assumption.evidence))
      || !uniqueStrings(assumption.provenance_tags, { required: true })) {
      errors.push(`assumption:${id}:invalid`);
    }
  }

  const attackerStories = idMap(model.attacker_stories, "story_id", "attacker-stories", errors);
  for (const [id, story] of attackerStories) {
    const threat = threats.get(story.threat_id);
    if (!actors.has(story.actor_id)
      || !entryPoints.has(story.entry_point_id)
      || !threat
      || !refsValid(story.affected_asset_ids, assets, { required: true })
      || !uniqueStrings(story.preconditions)
      || !uniqueStrings(story.steps, { required: true })
      || story.steps.length < 2
      || !nonEmptyString(story.outcome)
      || !nonEmptyEvidence(story.evidence)
      || !uniqueStrings(story.provenance_tags, { required: true })
      || !threat.actor_ids.includes(story.actor_id)
      || !threat.entry_point_ids.includes(story.entry_point_id)
      || story.affected_asset_ids.some(assetId => !threat.asset_ids.includes(assetId))) {
      errors.push(`attacker-story:${id}:invalid`);
    }
  }
  for (const threatId of threats.keys()) {
    if (![...attackerStories.values()].some(story => story.threat_id === threatId)) {
      errors.push(`threat:${threatId}:attacker-story-missing`);
    }
  }

  const outOfScopeStories = idMap(model.out_of_scope_stories, "story_id", "out-of-scope-stories", errors);
  for (const [id, story] of outOfScopeStories) {
    if (!nonEmptyString(story.scenario)
      || !nonEmptyString(story.reason)
      || !uniqueStrings(story.reconsider_when, { required: true })
      || !nonEmptyEvidence(story.evidence)
      || !uniqueStrings(story.provenance_tags, { required: true })) {
      errors.push(`out-of-scope-story:${id}:invalid`);
    }
  }

  const calibration = model.severity_calibration;
  if (!isObject(calibration)
    || !nonEmptyString(calibration.model)
    || !Array.isArray(calibration.levels)
    || !uniqueStrings(calibration.context_notes)
    || !nonEmptyEvidence(calibration.evidence)) {
    errors.push("severity-calibration-invalid");
  } else {
    const observedLevels = calibration.levels.map(level => level?.severity);
    if (observedLevels.length !== THREAT_SEVERITIES.length
      || new Set(observedLevels).size !== observedLevels.length
      || THREAT_SEVERITIES.some(severity => !observedLevels.includes(severity))) {
      errors.push("severity-calibration-levels-invalid");
    }
    for (const level of calibration.levels) {
      if (!isObject(level)
        || !uniqueStrings(level.criteria, { required: true })
        || !Array.isArray(level.examples)
        || (level.examples.length === 0 && !nonEmptyString(level.not_applicable_reason))) {
        errors.push(`severity-calibration:${level?.severity ?? "unknown"}:invalid`);
        continue;
      }
      for (const example of level.examples) {
        if (!isObject(example)
          || !nonEmptyString(example.scenario)
          || !nonEmptyString(example.rationale)
          || !refsValid(example.threat_ids, threats)) {
          errors.push(`severity-calibration:${level.severity}:example-invalid`);
        }
      }
    }
  }

  if (!Array.isArray(model.deprioritized)
    || !Array.isArray(model.history_clusters)
    || !Array.isArray(model.entry_point_coverage)
    || !Array.isArray(model.open_questions)
    || !isObject(model.provenance)) {
    errors.push("threat-model-supporting-sections-invalid");
  }
  if (context.requireDigest !== false && model.manifest_digest !== threatModelDigest(model)) {
    errors.push("threat-model-digest-invalid");
  }
  return [...new Set(errors)];
}
