#!/usr/bin/env node

import { access, chmod, mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { probeEngines, runSemgrepScan, selectEngine } from "../scripts/semgrep-core.mjs";

const executeFile = promisify(execFile);
const SEMGREP_CLI = fileURLToPath(new URL("../scripts/semgrep-scan.mjs", import.meta.url));

async function expectReject(operation, pattern) {
  try {
    await operation();
  } catch (error) {
    if (pattern.test(error.message)) return;
    throw new Error(`Operation failed for the wrong reason: ${error.message}`);
  }
  throw new Error("Expected operation to fail");
}

async function main() {
  const workspace = await mkdtemp(join(tmpdir(), "opencode-semgrep-test-"));
  const external = await mkdtemp(join(tmpdir(), "opencode-semgrep-external-"));
  try {
    await mkdir(join(workspace, "rules"), { recursive: true });
    await mkdir(join(workspace, "src"), { recursive: true });
    await writeFile(join(workspace, "rules", "test.yaml"), `rules:
  - id: fixture.rule
    pattern: eval(...)
    message: fixture
    languages: [javascript]
    severity: WARNING
`, "utf8");
    await writeFile(join(workspace, "src", "app.js"), "eval(input);\n", "utf8");
    const fakeEngine = join(workspace, "fake-opengrep.mjs");
    await writeFile(fakeEngine, `#!/usr/bin/env node
if (process.argv.includes("--version")) {
  process.stdout.write("OpenGrep fixture 1.0.0\\\\n");
  process.exit(0);
}
if (process.argv.includes("--metrics=off")) {
  process.stderr.write("OpenGrep fixture rejects Semgrep-only --metrics=off\\\\n");
  process.exit(2);
}
process.stderr.write("D".repeat(500000));
process.stdout.write(JSON.stringify({
  version: "fixture",
  results: [{
    check_id: "fixture.rule",
    path: "src/app.js",
    start: { line: 1, col: 1 },
    end: { line: 1, col: 12 },
    extra: {
      message: "Fixture finding",
      severity: "WARNING",
      metadata: { category: "security" },
      metavars: {},
      lines: "eval(input);",
      fingerprint: "fixture-fingerprint"
    }
  }],
  errors: Array.from({ length: 100 }, (_, index) => ({
    message: "E".repeat(2000),
    index
  })),
  paths: { scanned: ["src/app.js"] }
}));
`, "utf8");
    await chmod(fakeEngine, 0o755);
    const environment = {
      ...process.env,
      OPENGREP_BIN: fakeEngine,
      SEMGREP_BIN: join(workspace, "missing-semgrep"),
      SEMGREP_ENGINE: "opengrep",
    };
    const probes = await probeEngines({ workspaceRoot: workspace, environment });
    if (!probes.find(item => item.engine === "opengrep")?.available) throw new Error("OpenGrep health probe did not detect the fixture engine");
    const fallback = await selectEngine({
      workspaceRoot: workspace,
      environment: {
        ...process.env,
        OPENGREP_BIN: join(workspace, "missing-opengrep"),
        SEMGREP_BIN: fakeEngine,
        SEMGREP_ENGINE: "auto",
      },
    });
    if (fallback.engine !== "semgrep") throw new Error("Auto mode did not fall back from OpenGrep to Semgrep");

    const scan = await runSemgrepScan({
      workspaceRoot: workspace,
      auditId: "fixture-audit",
      sessionId: "fixture-scan-r1",
      agentName: "web-source-auditor",
      targetPath: "src",
      rulePaths: ["rules/test.yaml"],
      environment,
    });
    if (scan.engine !== "opengrep" || scan.findings !== 1 || scan.error_count !== 100
      || scan.error_samples.length !== 5 || scan.error_samples.some(error => Buffer.byteLength(error) > 550)) {
      throw new Error("OpenGrep-compatible scan result was not normalized and bounded");
    }
    if (!scan.raw_output_path.startsWith("tmp/fixture-audit/semgrep/")) throw new Error("Raw scan output is not scoped by audit_id");
    if (scan.stderr_bytes !== 500000 || !scan.stderr_path
      || (await readFile(resolve(workspace, scan.stderr_path))).length !== 500000) {
      throw new Error("Scanner stderr was not retained outside the CLI summary");
    }
    const sarif = JSON.parse(await readFile(resolve(workspace, scan.sarif_path), "utf8"));
    if (sarif.runs.length !== 1 || sarif.runs[0].results[0].ruleId !== "fixture.rule"
      || sarif.runs[0].results[0].partialFingerprints.semgrepFingerprint !== "fixture-fingerprint") {
      throw new Error("Semgrep JSON was not normalized to SARIF 2.1.0");
    }
    const commandLine = sarif.runs[0].invocations[0].commandLine;
    if (commandLine.includes(workspace) || commandLine.includes(await realpath(workspace))) {
      throw new Error("SARIF command line leaked the absolute workspace path");
    }

    const splitSource = join(external, "source");
    const splitEngine = join(external, "engine");
    const splitReports = join(external, "reports");
    const splitTmp = join(external, "tmp");
    const splitExecution = join(workspace, "split-execution");
    await Promise.all([
      mkdir(join(splitSource, "src"), { recursive: true }),
      mkdir(join(splitEngine, ".opencode", "rules"), { recursive: true }),
      mkdir(splitReports, { recursive: true }),
      mkdir(splitTmp, { recursive: true }),
      mkdir(splitExecution, { recursive: true }),
    ]);
    await Promise.all([
      writeFile(join(splitSource, "src", "app.js"), "eval(input);\n", "utf8"),
      writeFile(join(splitEngine, ".opencode", "rules", "test.yaml"), await readFile(join(workspace, "rules", "test.yaml"))),
      symlink(splitSource, join(splitExecution, "source"), "dir"),
      symlink(join(splitEngine, ".opencode"), join(splitExecution, ".opencode"), "dir"),
      symlink(splitReports, join(splitExecution, "reports"), "dir"),
      symlink(splitTmp, join(splitExecution, "tmp"), "dir"),
    ]);
    const splitEnvironment = {
      ...environment,
      AUDIT_SOURCE_ROOT: splitSource,
      AUDIT_ENGINE_ROOT: splitEngine,
      AUDIT_WORKSPACE_ROOT: splitExecution,
      AUDIT_REPORTS_ROOT: splitReports,
      AUDIT_TMP_ROOT: splitTmp,
    };
    const splitScan = await runSemgrepScan({
      workspaceRoot: splitExecution,
      auditId: "fixture-split-audit",
      sessionId: "fixture-split-r1",
      agentName: "web-source-auditor",
      targetPath: join(splitSource, "src"),
      rulePaths: [".opencode/rules/test.yaml"],
      environment: splitEnvironment,
    });
    if (splitScan.target_path !== "src" || !splitScan.raw_output_path.startsWith("tmp/fixture-split-audit/")
      || !splitScan.sarif_path.startsWith("reports/sarif/")) throw new Error("Split audit roots were not preserved in scanner output paths");
    await access(join(splitTmp, splitScan.raw_output_path.slice("tmp/".length)));
    await access(join(splitReports, splitScan.sarif_path.slice("reports/".length)));
    await expectReject(() => access(join(splitSource, "reports")), /ENOENT/);
    await expectReject(() => access(join(splitSource, "tmp")), /ENOENT/);

    const merged = await runSemgrepScan({
      workspaceRoot: workspace,
      auditId: "fixture-audit",
      sessionId: "fixture-scan-r1",
      agentName: "web-source-auditor",
      targetPath: "src",
      rulePaths: ["rules"],
      environment,
    });
    if (merged.sarif_runs !== 2) throw new Error("A second static-analysis run did not merge into the session SARIF");

    const cliResult = await executeFile(process.execPath, [
      SEMGREP_CLI,
      "scan",
      "--audit-id", "fixture-audit",
      "--session-id", "fixture-cli-r1",
      "--agent-name", "web-source-auditor",
      "--target", "src",
      "--rule", "rules/test.yaml",
    ], {
      cwd: workspace,
      env: environment,
      maxBuffer: 20_000,
    });
    const cliSummary = JSON.parse(cliResult.stdout);
    if (cliSummary.complete !== true || cliSummary.transport !== "direct-cli" || cliSummary.findings !== 1) {
      throw new Error("Direct Semgrep/OpenGrep CLI did not return the expected bounded summary");
    }
    if (Buffer.byteLength(cliResult.stdout) > 16 * 1024 || cliResult.stderr !== "") {
      throw new Error("Direct Semgrep/OpenGrep CLI leaked scanner output to the invoking context");
    }

    const concurrentArgs = [
      SEMGREP_CLI,
      "scan",
      "--audit-id", "fixture-audit",
      "--session-id", "fixture-cli-concurrent-r1",
      "--agent-name", "web-source-auditor",
      "--target", "src",
      "--rule", "rules/test.yaml",
    ];
    const concurrentRuns = await Promise.all([
      executeFile(process.execPath, concurrentArgs, { cwd: workspace, env: environment, maxBuffer: 20_000 }),
      executeFile(process.execPath, concurrentArgs, { cwd: workspace, env: environment, maxBuffer: 20_000 }),
    ]);
    if (concurrentRuns.some(run => Buffer.byteLength(run.stdout) > 16 * 1024 || run.stderr !== "")) {
      throw new Error("Concurrent direct scans leaked scanner output to the invoking context");
    }
    const concurrentSarif = JSON.parse(await readFile(
      join(workspace, "reports", "sarif", "web-source-auditor.fixture-cli-concurrent-r1.sarif"),
      "utf8",
    ));
    if (concurrentSarif.runs.length !== 2) {
      throw new Error("Concurrent direct scans lost a SARIF run");
    }

    await expectReject(() => runSemgrepScan({
      workspaceRoot: workspace,
      auditId: "fixture-audit",
      sessionId: "fixture-escape-r1",
      agentName: "web-source-auditor",
      targetPath: "src",
      rulePaths: ["../outside-rules.yaml"],
      environment,
    }), /escapes workspace/);
    await writeFile(join(external, "external-rule.yaml"), "rules: []\n", "utf8");
    await symlink(join(external, "external-rule.yaml"), join(workspace, "rules", "external-rule.yaml"));
    await expectReject(() => runSemgrepScan({
      workspaceRoot: workspace,
      auditId: "fixture-audit",
      sessionId: "fixture-rule-symlink-r1",
      agentName: "web-source-auditor",
      targetPath: "src",
      rulePaths: ["rules/external-rule.yaml"],
      environment,
    }), /Symlink target escapes workspace/);
    await expectReject(() => runSemgrepScan({
      workspaceRoot: workspace,
      auditId: "fixture-audit",
      sessionId: "fixture-output-r1",
      agentName: "web-source-auditor",
      targetPath: "src",
      rulePaths: ["rules/test.yaml"],
      sarifPath: "tmp/not-durable.sarif",
      environment,
    }), /reports\/sarif/);
    await rm(join(workspace, "reports", "sarif"), { recursive: true, force: true });
    await symlink(external, join(workspace, "reports", "sarif"));
    await expectReject(() => runSemgrepScan({
      workspaceRoot: workspace,
      auditId: "fixture-audit",
      sessionId: "fixture-symlink-r1",
      agentName: "web-source-auditor",
      targetPath: "src",
      rulePaths: ["rules/test.yaml"],
      environment,
    }), /Symlink target escapes workspace/);

    process.stdout.write(`${JSON.stringify({
      complete: true,
      opengrep_compatibility: true,
      semgrep_fallback_supported: true,
      direct_cli: true,
      bounded_cli_summary: true,
      bounded_error_samples: true,
      stderr_retained_on_disk: true,
      concurrent_sarif_merge: true,
      local_rules_only: true,
      normalized_sarif: true,
      merged_sarif_runs: merged.sarif_runs,
      path_escape_rejected: true,
      rule_symlink_escape_rejected: true,
      symlink_escape_rejected: true,
      non_durable_sarif_rejected: true,
      split_audit_roots: true,
    })}\n`);
  } finally {
    await rm(workspace, { recursive: true, force: true });
    await rm(external, { recursive: true, force: true });
  }
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
