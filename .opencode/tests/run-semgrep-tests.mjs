#!/usr/bin/env node

import { chmod, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { probeEngines, runSemgrepScan, selectEngine } from "../mcp/semgrep-core.mjs";

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
  errors: [],
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
    if (scan.engine !== "opengrep" || scan.findings !== 1 || scan.errors.length !== 0) throw new Error("OpenGrep-compatible scan result was not normalized");
    if (!scan.raw_output_path.startsWith("tmp/fixture-audit/semgrep/")) throw new Error("Raw scan output is not scoped by audit_id");
    const sarif = JSON.parse(await readFile(resolve(workspace, scan.sarif_path), "utf8"));
    if (sarif.runs.length !== 1 || sarif.runs[0].results[0].ruleId !== "fixture.rule"
      || sarif.runs[0].results[0].partialFingerprints.semgrepFingerprint !== "fixture-fingerprint") {
      throw new Error("Semgrep JSON was not normalized to SARIF 2.1.0");
    }

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
      local_rules_only: true,
      normalized_sarif: true,
      merged_sarif_runs: merged.sarif_runs,
      path_escape_rejected: true,
      rule_symlink_escape_rejected: true,
      symlink_escape_rejected: true,
      non_durable_sarif_rejected: true,
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
