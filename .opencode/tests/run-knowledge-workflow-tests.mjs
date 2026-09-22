import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { knowledgeEnvironment, parseKnowledgeArgs, queryKnowledge } from "../lib/knowledge-workflow.mjs";

if (!["win32", "linux"].includes(process.platform)) throw new Error("知识库对接回归留待 Windows/Linux 执行。");
const execute = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "audit-knowledge-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await Promise.all(["src/knowledge_factory", "knowledge/catalog/quality/mechanisms", "knowledge/detectors"].map(path => mkdir(join(root, path), { recursive: true })));
  await writeFile(join(root, "src/knowledge_factory/kb_index.py"), "# fixture\n");
  return root;
}

test("知识库路径按平台目录解析，支持带空格的外部路径", () => {
  const root = resolve("fixture platform");
  assert.equal(knowledgeEnvironment(root, {}).AUDIT_KNOWLEDGE_ROOT, resolve(root, "../KnowledgeWorkFlow"));
  assert.equal(knowledgeEnvironment(root, { AUDIT_KNOWLEDGE_ROOT: "../Updated Knowledge" }).AUDIT_KNOWLEDGE_ROOT, resolve(root, "../Updated Knowledge"));
  assert.equal(knowledgeEnvironment(root, {}).AUDIT_KNOWLEDGE_CLI, join(root, ".opencode/scripts/knowledge-query.mjs"));
});

test("默认优先根因，精确查询、四轴筛选和分页不丢失", () => {
  const request = parseKnowledgeArgs(["search", "--track", "coverage", "--query", "授权边界", "--filter", "weakness=CWE-862", "--filter", "weakness=CWE-863", "--filter", "surface=mcp", "--offset", "10"]);
  assert.equal(request.kind, "mechanism"); assert.equal(request.limit, 5); assert.equal(request.offset, 10);
  assert.deepEqual(request.filters, { weakness: ["CWE-862", "CWE-863"], surface: ["mcp"] });
  assert.equal(parseKnowledgeArgs(["search", "--track", "seeded-variant", "--kind", "case", "--mode", "exact", "--query", "CVE-2024-11958"]).mode, "exact");
  for (const args of [["search", "--query", "x"], ["show", "--track", "coverage"], ["status", "--limit", "11"], ["scan"], ["status", "--filter", "__proto__=x"]]) assert.throws(() => parseKnowledgeArgs(args));
});

test("blind、关闭或库缺失时不启动检索进程", async t => {
  const root = await fixture(t); let calls = 0;
  const options = { environment: {}, execute: async () => { calls++; throw new Error("不应执行"); } };
  assert.equal((await queryKnowledge({ command: "search", root, track: "blind" }, options)).status, "SKIPPED");
  assert.equal((await queryKnowledge({ command: "status", root }, { ...options, environment: { AUDIT_KNOWLEDGE_ENABLED: "false" } })).status, "SKIPPED");
  assert.equal((await queryKnowledge({ command: "status", root: join(root, "missing") }, options)).status, "UNAVAILABLE");
  assert.equal(calls, 0);
});

test("原生质量状态原样返回，命令参数不经过 shell，禁止写字节码", async t => {
  const root = await fixture(t);
  const response = { schema_version: "audit-knowledge-query.v1", status: "PARTIAL", read_only: true,
    automatic_vulnerability_verdict: false, warnings: ["根因卡证据陈旧"], results: [{
      source: { path: "knowledge/catalog/cases/example.yaml", sha256: "a".repeat(64) },
      quality: { validation: "original_case_only", generalization: "not_evaluated" }, mechanism_status: { evidence_status: "stale" },
    }] };
  const request = parseKnowledgeArgs(["search", "--track", "coverage", "--root", root, "--query", "$(not-a-command) `literal`"]);
  const actual = await queryKnowledge(request, { environment: { AUDIT_KNOWLEDGE_PYTHON: "fixture python" }, execute: async (command, args, options) => {
    assert.equal(command, "fixture python"); assert.equal(options.shell, false);
    assert.deepEqual(args.slice(0, 2), ["-I", "-B"]); assert.equal(args[3], root);
    assert.equal(JSON.parse(args[4]).query, request.query); return { stdout: JSON.stringify(response) };
  } });
  assert.deepEqual(actual, response);
  for (const stdout of ["not json", JSON.stringify({ ...response, automatic_vulnerability_verdict: true })]) {
    assert.equal((await queryKnowledge(request, { environment: {}, execute: async () => ({ stdout }) })).status, "UNAVAILABLE");
  }
});

test("Python 适配器保留原生根因、反例、修订和过期状态", async () => {
  const python = process.env.AUDIT_KNOWLEDGE_PYTHON || (process.platform === "win32" ? "python" : "python3");
  await execute(python, ["-I", "-B", join(here, "knowledge-workflow-fixture.py")], { shell: false, windowsHide: true, timeout: 30000 });
});

test("选定新版知识库的原生索引集成回归", { skip: !process.env.AUDIT_TEST_KNOWLEDGE_ROOT }, async () => {
  const root = process.env.AUDIT_TEST_KNOWLEDGE_ROOT;
  const status = await queryKnowledge(parseKnowledgeArgs(["status", "--root", root]));
  assert.ok(["READY", "PARTIAL"].includes(status.status), status.reason);
  assert.ok(status.stats.by_kind.mechanism > 0);
  const page = await queryKnowledge(parseKnowledgeArgs(["search", "--root", root, "--track", "coverage", "--mode", "filter", "--limit", "1"]));
  assert.ok(["READY", "PARTIAL"].includes(page.status), page.reason);
  assert.equal(page.results.length, 1);
  const detail = await queryKnowledge(parseKnowledgeArgs(["show", "--root", root, "--track", "coverage", "--id", page.results[0].uid]));
  assert.ok(["READY", "PARTIAL"].includes(detail.status), detail.reason);
  assert.equal(detail.document.source.sha256, page.results[0].source.sha256);
  assert.ok(detail.document.payload.security_invariant);
  assert.ok(Array.isArray(detail.document.payload.counterexamples));
  assert.ok(Array.isArray(detail.document.detectors));
});
