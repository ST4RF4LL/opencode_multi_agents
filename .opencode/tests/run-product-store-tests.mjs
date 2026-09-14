import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProductStore, UNDEFINED_PRODUCT_ID } from "../web/dynamic-validation-observatory/product-store.mjs";

const root = await mkdtemp(join(tmpdir(), "opencode-product-store-"));
const source = join(root, "source");
const sourceTwo = join(root, "source-two");
let store;
try {
  await Promise.all([mkdir(source), mkdir(sourceTwo)]);
  store = new ProductStore({ path: join(root, "state", "product-catalog.sqlite"), platformRoot: join(root, "platform") });
  await store.ready;

  const builtIn = (await store.listProducts({ page: 1, page_size: 20 })).items.find(item => item.id === UNDEFINED_PRODUCT_ID);
  assert.equal(builtIn?.system, true);

  const product = await store.createProduct({ name: "支付平台", description: "回归测试产品空间", tags: ["支付"] });
  assert.equal(product.status, "active");

  const target = await store.createTarget(product.id, {
    name: "支付 API",
    version_label: "release-test",
    source_scopes: [{ name: "api", path: source, include_patterns: ["src/**/*.js"], exclude_patterns: ["node_modules/**"] }],
  });
  assert.equal(target.source_scopes.length, 1);
  assert.equal(target.availability, "available");

  const snapshot = await store.targetExecutionSnapshot(product.id, target.id);
  assert.equal(snapshot.snapshot.target_id, target.id);
  assert.match(snapshot.digest, /^[a-f0-9]{64}$/);
  await store.linkAudit({ auditId: "audit-product-store-test", productId: product.id, targetId: target.id, snapshot: snapshot.snapshot, snapshotDigest: snapshot.digest });
  assert.equal(store.auditLink("audit-product-store-test")?.target_id, target.id);
  await assert.rejects(() => store.deleteTarget(product.id, target.id, target.version), error => error.code === "target-has-audits");
  const edited = await store.updateTarget(product.id, target.id, {
    name: "支付 API 新名称", test_focus: "权限边界", source_scopes: [{ ...target.source_scopes[0], path: sourceTwo }],
  }, target.version);
  assert.equal(edited.name, "支付 API 新名称");
  assert.equal(edited.test_focus, "权限边界");
  assert.equal(edited.source_scopes[0].path, sourceTwo);
  assert.equal(edited.source_scopes[0].id, target.source_scopes[0].id);
  assert.deepEqual(edited.source_scopes[0].include_patterns, target.source_scopes[0].include_patterns);
  assert.equal(edited.storage_namespace, target.storage_namespace);
  assert.deepEqual(store.auditLink("audit-product-store-test").snapshot, snapshot.snapshot);
  await assert.rejects(() => store.updateTarget(product.id, target.id, { name: "过期修改" }, target.version), error => error.code === "version-mismatch");

  const temporary = await store.createTarget(UNDEFINED_PRODUCT_ID, {
    name: "临时目录对象",
    source_scopes: [{ name: "source", path: sourceTwo }],
  }, { origin: "temporary" });
  const temporarySnapshot = await store.targetExecutionSnapshot(UNDEFINED_PRODUCT_ID, temporary.id);
  await store.linkAudit({ auditId: "audit-transfer-test", productId: UNDEFINED_PRODUCT_ID, targetId: temporary.id, snapshot: temporarySnapshot.snapshot, snapshotDigest: temporarySnapshot.digest });
  assert.ok((await store.auditLinksForProduct(UNDEFINED_PRODUCT_ID)).has("audit-transfer-test"));
  const transferred = await store.transferTarget(UNDEFINED_PRODUCT_ID, temporary.id, product.id, temporary.version);
  assert.equal(transferred.product_id, product.id);
  assert.equal(transferred.ownership_generation, temporary.ownership_generation + 1);
  assert.equal(transferred.storage_namespace, temporary.storage_namespace);
  assert.equal((await store.auditLinksForProduct(UNDEFINED_PRODUCT_ID)).has("audit-transfer-test"), false);
  assert.ok((await store.auditLinksForProduct(product.id)).has("audit-transfer-test"));
  const historicalLink = store.auditLink("audit-transfer-test");
  assert.equal(historicalLink.product_id_at_creation, UNDEFINED_PRODUCT_ID);
  assert.deepEqual(historicalLink.snapshot, temporarySnapshot.snapshot);
  assert.equal(historicalLink.snapshot_digest, temporarySnapshot.digest);

  const events = await store.listProductEvents(product.id);
  assert.ok(events.some(event => event.type === "target.transferred_in"));
  console.log("产品目录库测试通过");
} finally {
  store?.close();
  await rm(root, { recursive: true, force: true });
}
