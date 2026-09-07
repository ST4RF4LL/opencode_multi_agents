import { createHash } from "node:crypto";

export const AI_COVERAGE_POLICY = "surface-dependency-v1";
const hash = value => createHash("sha256").update(JSON.stringify(value)).digest("hex");
export function aiRoutingDigest(value) { const copy = { ...value }; delete copy.routing_digest; return hash(copy); }
const states = new Set(["RELEVANT", "DEPENDENCY", "NOT_APPLICABLE", "UNKNOWN"]);
const nonempty = value => typeof value === "string" && value.trim().length > 0;

export function buildAiRouting(scope, decisions) {
  const files = new Map((scope.files ?? []).filter(file => file.review_required).map(file => [file.file_id, file]));
  if (!Array.isArray(decisions) || decisions.length !== files.size) throw new Error("AI 适用性必须逐文件覆盖冻结范围。");
  const sourcePaths = new Set([...files.values()].map(file => file.path));
  const byId = new Map();
  for (const entry of decisions) {
    if (!files.has(entry.file_id) || byId.has(entry.file_id) || !states.has(entry.state)
      || !nonempty(entry.reason) || !Array.isArray(entry.evidence_refs) || !entry.evidence_refs.length || !entry.evidence_refs.every(nonempty)
      || !Array.isArray(entry.depends_on_file_ids) || new Set(entry.depends_on_file_ids).size !== entry.depends_on_file_ids.length
      || entry.depends_on_file_ids.some(id => !files.has(id) || id === entry.file_id)) throw new Error("AI 适用性记录缺失证据、含重复或引用越界。");
    if (entry.evidence_refs.some(ref => !sourcePaths.has(ref.replace(/:\d+(?:-\d+)?$/, "")))) throw new Error("AI 筛查证据必须引用冻结范围内的源码路径，可附行号。");
    byId.set(entry.file_id, { file_id: entry.file_id, state: entry.state, reason: entry.reason, evidence_refs: entry.evidence_refs, depends_on_file_ids: entry.depends_on_file_ids });
  }
  const selected = new Set([...byId.values()].filter(row => row.state !== "NOT_APPLICABLE").map(row => row.file_id));
  // Both callers and dependencies can carry AI-boundary data or privileges.
  const adjacency = new Map([...files.keys()].map(id => [id, new Set()]));
  for (const row of byId.values()) for (const id of row.depends_on_file_ids) {
    adjacency.get(row.file_id).add(id); adjacency.get(id).add(row.file_id);
  }
  const queue = [...selected];
  for (let index = 0; index < queue.length; index++) for (const id of adjacency.get(queue[index])) if (!selected.has(id)) { selected.add(id); queue.push(id); }
  const negatives = [...files.keys()].filter(id => !selected.has(id)).sort((a, b) => hash([scope.scope_digest, a]).localeCompare(hash([scope.scope_digest, b])));
  const samples = negatives.slice(0, Math.min(5, Math.ceil(negatives.length * 0.1)));
  for (const id of samples) selected.add(id);
  const value = {
    schema_version: 1, policy: AI_COVERAGE_POLICY, audit_id: scope.audit_id, scope_digest: scope.scope_digest,
    source_bindings: [...files.values()].map(file => ({ file_id: file.file_id, sha256: file.sha256 ?? null })).sort((a, b) => a.file_id.localeCompare(b.file_id)),
    decisions: [...byId.values()].sort((a, b) => a.file_id.localeCompare(b.file_id)),
    required_file_ids: [...selected].sort(), sample_file_ids: samples.sort(),
    unknown_file_ids: [...byId.values()].filter(row => row.state === "UNKNOWN").map(row => row.file_id).sort(),
    excluded_file_ids: [...files.keys()].filter(id => !selected.has(id)).sort(),
  };
  value.routing_digest = aiRoutingDigest(value);
  return value;
}

export function validateAiRouting(scope) {
  if (!scope.ai_routing && scope.policy?.ai_coverage !== AI_COVERAGE_POLICY) return [];
  try {
    const expected = buildAiRouting(scope, scope.ai_routing?.decisions);
    if (JSON.stringify(scope.ai_routing) !== JSON.stringify(expected)) return ["AI 适用性路由与冻结范围或确定性选择不匹配。"];
    return [];
  } catch (error) { return [error.message]; }
}

const cache = new WeakMap();
export function aiRequired(scope, entity) {
  if (!scope) return true;
  if (!cache.has(scope)) {
    const errors = validateAiRouting(scope);
    if (errors.length) throw new Error(errors.join("；"));
    cache.set(scope, scope.ai_routing ? new Set(scope.ai_routing.required_file_ids) : null);
  }
  const selected = cache.get(scope);
  if (selected === null) return true; // historical frozen scopes retain their policy
  const id = entity.file_id ?? scope.files?.find(file => file.path === entity.path)?.file_id;
  if (!id) throw new Error("实体缺少用于 AI 适用性路由的文件绑定。");
  return selected.has(id);
}
