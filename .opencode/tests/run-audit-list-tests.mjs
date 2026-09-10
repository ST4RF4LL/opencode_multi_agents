import assert from "node:assert/strict";
import { paginateAudits, compactWorkspaceAudits } from "../web/dynamic-validation-observatory/audit-list.mjs";

const audits = Array.from({ length: 125 }, (_, index) => ({
  id: `audit-${String(index).padStart(3, "0")}`, name: `任务 ${index}`, status: "completed",
  repository_name: "测试仓库", updated_at: "2026-09-08T00:00:00Z", stages: ["large detail"],
}));
const query = value => new URLSearchParams(value);
for (const size of [20, 30, 50, 100]) {
  const result = paginateAudits(audits, query({ tab: "completed", page_size: size, page: 2 }));
  assert.equal(result.items.length, Math.min(size, 125 - size));
  assert.equal(result.items[0].id, audits[size].id);
  assert.equal(result.count, 125);
  assert.equal(result.total_pages, Math.ceil(125 / size));
  assert.equal("stages" in result.items[0], false);
}
assert.equal(paginateAudits(audits, query({})).items.length, 20);
assert.equal(paginateAudits(audits, query({ page: 999 })).page, 7);
assert.equal(paginateAudits(audits, query({ q: "audit-124" })).items[0].id, "audit-124");
assert.equal(paginateAudits(audits, query({ q: "不存在" })).total_pages, 1);
const statuses = ["preparing", "recovering", "running", "pausing", "cancelling", "paused", "queued", "interrupted", "cancelled", "failed", "completed", "artifact_only", "unknown"];
const mixed = statuses.map((status, index) => ({ ...audits[index], status }));
assert.deepEqual(paginateAudits(mixed, query({ tab: "running" })).items.map(item => item.status), statuses.slice(0, 5));
assert.deepEqual(paginateAudits(mixed, query({ tab: "completed" })).items.map(item => item.status), statuses.slice(5));
const running = paginateAudits(audits.map(item => ({ ...item, status: "running" })), query({ tab: "running", page: 5 }));
assert.equal(running.items.length, 125);
assert.equal(running.page, 1);
assert.equal(running.page_size, null);
assert.equal(compactWorkspaceAudits(audits).length, 5);
assert.equal(compactWorkspaceAudits([...audits, { id: "active", status: "running" }]).length, 6);
for (const parameters of [{ tab: "invalid" }, { page_size: 21 }, { page: 0 }, { page: 1.5 }, { page: "NaN" }]) {
  assert.throws(() => paginateAudits(audits, query(parameters)), error => error.statusCode === 422);
}
console.log("审计任务分类、分页、搜索和轻量快照检查通过。");
