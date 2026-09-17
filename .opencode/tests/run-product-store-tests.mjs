import assert from "node:assert/strict";
import { mkdtemp, mkdir, realpath, rm } from "node:fs/promises";
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
  assert.equal(edited.source_scopes[0].path, await realpath(sourceTwo));
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

  const destination = await store.createProduct({ name: "归属修正产品" });
  const moved = await store.transferTarget(product.id, transferred.id, destination.id, transferred.version);
  assert.equal(moved.product_id, destination.id);
  assert.equal(moved.storage_namespace, transferred.storage_namespace);
  assert.equal(moved.ownership_generation, transferred.ownership_generation + 1);
  assert.ok((await store.auditLinksForProduct(destination.id)).has("audit-transfer-test"));
  assert.equal((await store.auditLinksForProduct(product.id)).has("audit-transfer-test"), false);
  const returned = await store.transferTarget(destination.id, moved.id, UNDEFINED_PRODUCT_ID, moved.version);
  assert.equal(returned.product_id, UNDEFINED_PRODUCT_ID);
  assert.deepEqual(store.auditLink("audit-transfer-test"), historicalLink);

  const batchPeer = await store.createTarget(UNDEFINED_PRODUCT_ID, {
    name: "批量归属对象", source_scopes: [{ name: "source", path: source }],
  });
  const selection = [{ id: returned.id, version: returned.version }, { id: batchPeer.id, version: batchPeer.version }];
  const beforeEvents = await store.listProductEvents(UNDEFINED_PRODUCT_ID);
  await assert.rejects(() => store.transferTargets(UNDEFINED_PRODUCT_ID,
    [selection[0], { ...selection[1], version: batchPeer.version + 1 }], destination.id), error => error.code === "version-mismatch");
  assert.deepEqual(store.getTarget(UNDEFINED_PRODUCT_ID, returned.id), returned);
  assert.deepEqual(store.getTarget(UNDEFINED_PRODUCT_ID, batchPeer.id), batchPeer);
  assert.deepEqual(await store.listProductEvents(UNDEFINED_PRODUCT_ID), beforeEvents);
  await assert.rejects(() => store.transferTargets(UNDEFINED_PRODUCT_ID, [selection[0], selection[0]], destination.id), error => error.code === "target-transfer-selection-invalid");
  await assert.rejects(() => store.transferTargets(UNDEFINED_PRODUCT_ID, [], destination.id), error => error.code === "target-transfer-selection-invalid");
  await assert.rejects(() => store.transferTargets(UNDEFINED_PRODUCT_ID, selection, UNDEFINED_PRODUCT_ID), error => error.code === "target-transfer-destination-invalid");
  await assert.rejects(() => store.transferTargets(product.id, selection, destination.id), error => error.code === "target-not-found");
  const archivedProduct = await store.createProduct({ name: "已归档目标产品" });
  await store.productAction(archivedProduct.id, "archive", archivedProduct.version);
  await assert.rejects(() => store.transferTargets(UNDEFINED_PRODUCT_ID, selection, archivedProduct.id), error => error.code === "product-archived");

  const batchMoved = await store.transferTargets(UNDEFINED_PRODUCT_ID, selection, destination.id);
  assert.equal(batchMoved.length, 2);
  for (const item of batchMoved) {
    assert.equal(item.product_id, destination.id);
    assert.equal(item.version, selection.find(target => target.id === item.id).version + 1);
  }
  assert.ok((await store.auditLinksForProduct(destination.id)).has("audit-transfer-test"));
  assert.deepEqual(store.auditLink("audit-transfer-test"), historicalLink);
  console.log("产品目录库测试通过");
} finally {
  store?.close();
  await rm(root, { recursive: true, force: true });
}
