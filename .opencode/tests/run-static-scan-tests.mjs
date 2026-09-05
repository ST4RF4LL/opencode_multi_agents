#!/usr/bin/env node

import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execute = promisify(execFile);
const CLI = fileURLToPath(new URL("../scripts/static-scan.mjs", import.meta.url));

async function invoke(workspace, args, environment = {}) {
  const result = await execute(process.execPath, [CLI, ...args], {
    cwd: workspace,
    env: { ...process.env, ...environment },
    maxBuffer: 64 * 1024,
  });
  return JSON.parse(result.stdout);
}

async function main() {
  const workspace = await mkdtemp(join(tmpdir(), "静态 扫描 "));
  try {
    await mkdir(join(workspace, "源码 空间"), { recursive: true });
    await mkdir(join(workspace, "rules"), { recursive: true });
    await writeFile(join(workspace, "源码 空间", "app.js"), "eval(input);\r\n", "utf8");
    await writeFile(join(workspace, "源码 空间", "package-lock.json"), "{}\r\n", "utf8");
    await writeFile(join(workspace, "rules", "rule.yaml"), "rules: []\n", "utf8");
    const fake = join(workspace, "fake-opengrep.mjs");
    await writeFile(fake, `#!/usr/bin/env node
if (process.argv.includes("--version")) { process.stdout.write("fixture 1.0.0\\n"); process.exit(0); }
process.stdout.write(JSON.stringify({ results: [{ check_id: "fixture.rule", path: "源码 空间/app.js", start: {line: 1, col: 1}, end: {line: 1, col: 5}, extra: {message: "fixture", severity: "WARNING"}}], errors: [], paths: {scanned: ["源码 空间/app.js"]} }));
`, "utf8");
    await chmod(fake, 0o755);
    const fakeNative = join(workspace, "fake-native-sarif.mjs");
    await writeFile(fakeNative, `#!/usr/bin/env node
import { writeFileSync } from "node:fs";
if (process.argv.includes("--version")) { process.stdout.write("fixture native 1.0.0\\n"); process.exit(0); }
const flag = process.argv.includes("--report-path") ? "--report-path" : "--output";
const output = process.argv[process.argv.indexOf(flag) + 1];
writeFileSync(output, JSON.stringify({ version: "2.1.0", runs: [{ tool: {driver: {name: flag === "--report-path" ? "Gitleaks" : "OSV-Scanner", version: "1.0.0"}}, results: [{ruleId: "fixture.native", message: {text: "fixture"}, locations: [{physicalLocation: {artifactLocation: {uri: "源码 空间/app.js"}, region: {startLine: 1}}}]}] }] }));
process.exit(1);
`, "utf8");
    await chmod(fakeNative, 0o755);
    const environment = { OPENGREP_BIN: fake, SEMGREP_BIN: join(workspace, "missing"), GITLEAKS_BIN: join(workspace, "missing-gitleaks"), OSV_SCANNER_BIN: join(workspace, "missing-osv") };

    const plan = await invoke(workspace, ["plan", "--target", "源码 空间"], environment);
    const rootPlanBefore = await invoke(workspace, ["plan", "--target", "."], environment);
    assert.equal(plan.scans.find(item => item.capability === "source_pattern_scan").status, "PLANNED");
    assert.equal(plan.scans.find(item => item.capability === "secret_scan").status, "SKIPPED");
    assert.equal(plan.scans.find(item => item.capability === "dependency_scan").status, "SKIPPED");
    assert.equal(plan.scans.find(item => item.capability === "deep_dataflow").status, "SKIPPED");

    const scan = await invoke(workspace, [
      "run", "--engine", "opengrep", "--audit-id", "fixture-audit", "--session-id", "fixture-session",
      "--agent-name", "web-source-auditor", "--target", "源码 空间", "--rule", "rules/rule.yaml",
    ], environment);
    assert.match(scan.scan_run_id, /^[a-f0-9]{64}$/);
    assert.equal(scan.findings, 1);
    const manifestPath = join(workspace, scan.run_manifest_path);
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    assert.equal(manifest.schema_version, "static-scan-run.v1");
    assert.equal(manifest.status, "SUCCESS");
    assert.equal(manifest.inputs.target_digest.length, 64);

    const runDirectory = join("reports", "static-analysis", "fixture-audit", scan.scan_run_id);
    const verified = await invoke(workspace, ["verify", "--run-dir", runDirectory], environment);
    assert.equal(verified.complete, true);

    const aggregate = await invoke(workspace, ["aggregate", "--audit-id", "fixture-audit", "--output", "reports/sarif/fixture.aggregate.sarif"], environment);
    assert.equal(aggregate.scan_runs, 1);
    const sarif = JSON.parse(await readFile(join(workspace, "reports", "sarif", "fixture.aggregate.sarif"), "utf8"));
    assert.equal(sarif.runs[0].automationDetails.id, scan.scan_run_id);
    const rootPlanAfter = await invoke(workspace, ["plan", "--target", "."], environment);
    assert.equal(rootPlanAfter.target_digest, rootPlanBefore.target_digest);

    const repeated = await invoke(workspace, [
      "run", "--engine", "opengrep", "--audit-id", "fixture-audit", "--session-id", "fixture-session-2",
      "--agent-name", "web-source-auditor", "--target", "源码 空间", "--rule", "rules/rule.yaml",
    ], environment);
    assert.equal(repeated.scan_run_id, scan.scan_run_id);

    const nativeEnvironment = { ...environment, GITLEAKS_BIN: fakeNative, OSV_SCANNER_BIN: fakeNative };
    for (const [engine, capability] of [["gitleaks", "secret_scan"], ["osv-scanner", "dependency_scan"]]) {
      const native = await invoke(workspace, [
        "run", "--engine", engine, "--audit-id", "fixture-native", "--session-id", `${engine}-session`,
        "--agent-name", "platform-security-auditor", "--target", "源码 空间",
      ], nativeEnvironment);
      assert.equal(native.complete, true);
      assert.equal(native.capability, capability);
      assert.equal(native.findings, 1);
    }

    process.stdout.write(`${JSON.stringify({ complete: true, windows_safe_paths: true, crlf_input: true, immutable_runs: true, deterministic_aggregate: true, optional_joern: true, gitleaks_adapter: true, osv_scanner_adapter: true })}\n`);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
