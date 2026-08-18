import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { arch as osArch, platform as osPlatform } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { resolveExecutablePath, resolvedOpenCodeExecutables } from "./executable-resolution.mjs";
import { isProxyEnvironmentVariable } from "./opencode-runtime-config.mjs";

const execFileAsync = promisify(execFile);
const LAUNCHER = fileURLToPath(new URL("./tmux-launcher.mjs", import.meta.url));
const SAFE_SOCKET = /^owa-[a-f0-9]{16}$/;
const SAFE_TARGET = /^audit:tui$/;
const SAFE_SESSION = /^[A-Za-z0-9._:-]{3,240}$/;
const MIN_COLUMNS = 40;
const MAX_COLUMNS = 320;
const MIN_ROWS = 12;
const MAX_ROWS = 120;

function runtimeOverrides(environment) {
  return Object.fromEntries(Object.entries(environment).filter(([key, value]) => (
    key.startsWith("OPENCODE_") || /^AUDIT_[A-Z0-9_]+$/.test(key) || isProxyEnvironmentVariable(key)
  ) && typeof value === "string"));
}

function sessionFromOutput(output) {
  for (const line of String(output ?? "").split(/\r?\n/)) {
    try {
      const value = JSON.parse(line);
      const sessionId = value?.sessionID ?? value?.session_id ?? value?.session?.id;
      if (SAFE_SESSION.test(sessionId ?? "")) return sessionId;
    } catch {}
  }
  return null;
}

export class OpenCodeTmuxMonitor {
  constructor({ stateRoot, command = null, tmuxCommand = null, environment = process.env, platform = osPlatform(), architecture = osArch(), execute = execFileAsync, resolveCommand = resolveExecutablePath } = {}) {
    this.stateRoot = stateRoot;
    this.environment = environment;
    this.platform = platform;
    this.architecture = architecture;
    this.command = command ?? environment.OPENCODE_BIN_PATH ?? environment.OPENCODE_BIN ?? (platform === "win32" ? "opencode.exe" : "opencode");
    this.tmuxCommand = tmuxCommand ?? environment.AUDIT_MULTIPLEXER_BIN ?? environment.PSMUX_BIN ?? environment.TMUX_BIN ?? null;
    this.execute = execute;
    this.resolveCommand = resolveCommand;
    this.probeResult = null;
    this.multiplexerBackend = null;
  }

  socketName(auditId) {
    return `owa-${createHash("sha256").update(`${this.stateRoot}\u0000${auditId}`).digest("hex").slice(0, 16)}`;
  }

  async probe({ force = false } = {}) {
    if (this.probeResult && !force) return this.probeResult;
    let openCodeError = null;
    let openCodeCommand = null;
    const openCodeCandidates = await resolvedOpenCodeExecutables({ command: this.command, environment: this.environment, platform: this.platform, architecture: this.architecture, resolveCommand: this.resolveCommand });
    for (const resolved of openCodeCandidates) {
      try {
        const run = await this.execute(resolved, ["run", "--help"], { encoding: "utf8", timeout: 10_000, maxBuffer: 1024 * 1024, env: this.environment, windowsHide: true });
        const help = `${run.stdout ?? ""}\n${run.stderr ?? ""}`;
        const missing = ["--format", "--session", "--agent", "--dir", "--title"].filter(flag => !help.includes(flag));
        if (missing.length) throw new Error(`OpenCode run 缺少 ${missing.join("、")}`);
        openCodeCommand = resolved;
        break;
      } catch (error) {
        openCodeError = error;
      }
    }
    if (openCodeCommand) this.command = openCodeCommand;

    let multiplexer = null;
    let multiplexerError = null;
    const multiplexerCandidates = this.platform === "win32"
      ? [this.tmuxCommand, "tmux.exe", "psmux.exe", "pmux.exe", "tmux", "psmux", "pmux"]
      : [this.tmuxCommand ?? "tmux"];
    for (const candidate of [...new Set(multiplexerCandidates.filter(Boolean))]) {
      const resolved = await this.resolveCommand(candidate, this.environment, this.platform);
      if (!resolved) continue;
      try {
        const version = await this.execute(resolved, ["-V"], { encoding: "utf8", timeout: 5_000, maxBuffer: 1024 * 1024, env: this.environment, windowsHide: true });
        const versionText = String(version.stdout || version.stderr || "").trim();
        const executableName = basename(resolved).toLowerCase();
        const backend = /psmux/i.test(versionText) || /^(?:psmux|pmux)(?:\.exe)?$/.test(executableName) ? "psmux" : "tmux";
        multiplexer = { command: resolved, backend, version: versionText };
        break;
      } catch (error) {
        multiplexerError = error;
      }
    }
    if (multiplexer) {
      this.tmuxCommand = multiplexer.command;
      this.multiplexerBackend = multiplexer.backend;
    }

    if (!openCodeCommand || !multiplexer) {
      const blockers = [];
      if (!openCodeCommand) blockers.push(`OpenCode CLI 不可用${openCodeError?.message ? `：${openCodeError.message}` : "；Windows 请设置 OPENCODE_BIN_PATH 指向 opencode.exe"}`);
      if (!multiplexer) blockers.push(`${this.platform === "win32" ? "psmux/tmux" : "tmux"} 不可用${multiplexerError?.message ? `：${multiplexerError.message}` : ""}`);
      this.probeResult = {
        available: false,
        backend: multiplexer?.backend ?? null,
        opencode_command: openCodeCommand,
        multiplexer_command: multiplexer?.command ?? null,
        tmux_version: multiplexer?.version ?? null,
        message: `终端监控不可用：${blockers.join("；")}`,
      };
      return this.probeResult;
    }
    this.probeResult = {
      available: true,
      backend: multiplexer.backend,
      opencode_command: openCodeCommand,
      multiplexer_command: multiplexer.command,
      tmux_version: multiplexer.version,
      message: `${multiplexer.backend === "psmux" ? "psmux" : "tmux"} 与 OpenCode run 已就绪。`,
    };
    return this.probeResult;
  }

  validateMetadata(terminal) {
    if (!SAFE_SOCKET.test(terminal?.socket_name ?? "") || !SAFE_TARGET.test(terminal?.target ?? "")) throw new Error("审计 tmux 元数据非法。");
  }

  async tmux(socketName, args, options = {}) {
    if (!SAFE_SOCKET.test(socketName)) throw new Error("tmux socket 名称非法。");
    return this.execute(this.tmuxCommand, ["-L", socketName, ...args], { encoding: "utf8", timeout: 10_000, maxBuffer: 2 * 1024 * 1024, ...options });
  }

  async targetLive(socketName, target) {
    if (!SAFE_TARGET.test(target)) return false;
    try {
      await this.tmux(socketName, ["list-panes", "-t", target]);
      return true;
    } catch {
      return false;
    }
  }

  async resize(terminal, columns, rows) {
    this.validateMetadata(terminal);
    const width = Number(columns);
    const height = Number(rows);
    if (!Number.isInteger(width) || width < MIN_COLUMNS || width > MAX_COLUMNS || !Number.isInteger(height) || height < MIN_ROWS || height > MAX_ROWS) {
      throw new Error(`tmux 窗口尺寸必须在 ${MIN_COLUMNS}-${MAX_COLUMNS} 列、${MIN_ROWS}-${MAX_ROWS} 行之间。`);
    }
    await this.tmux(terminal.socket_name, ["resize-window", "-t", terminal.target, "-x", String(width), "-y", String(height)]);
    const result = await this.tmux(terminal.socket_name, ["display-message", "-p", "-t", terminal.target, "#{window_width} #{window_height}"]);
    const [actualColumns, actualRows] = String(result.stdout ?? "").trim().split(/\s+/).map(Number);
    if (!Number.isInteger(actualColumns) || !Number.isInteger(actualRows)) throw new Error("无法读取调整后的 tmux 窗口尺寸。");
    return { columns: actualColumns, rows: actualRows };
  }

  async initialRunOutput(terminal) {
    // A newly created OpenCode process can legitimately be silent while it loads
    // configuration and the provider.  In particular, psmux on Windows does not
    // guarantee that pane output is observable before that initialization ends.
    // Process creation is the startup boundary; output is relayed asynchronously.
    try {
      const state = JSON.parse(await readFile(terminal.exit_path, "utf8"));
      const output = await readFile(terminal.output_path, "utf8").catch(() => "");
      throw new Error(`OpenCode run 在启动后立即退出（code=${state.code ?? "null"}, signal=${state.signal ?? "none"}）：${String(output || state.error || "无输出").trim().slice(-2_000)}`);
    } catch (error) {
      if (error?.code !== "ENOENT" && !(error instanceof SyntaxError)) throw error;
    }
    const deadline = Date.now() + (this.multiplexerBackend === "psmux" ? 0 : 2_000);
    do {
      try {
        const output = await this.capture(terminal, 120);
        if (output.trim()) return output;
      } catch {
        // A pane can take a moment to become capturable; output remains optional.
      }
      if (Date.now() >= deadline) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    } while (true);
    return "";
  }

  async start({ audit, repository, environment, executionDirectory = repository.path, providerSessionId = null, args }) {
    const probe = await this.probe();
    if (!probe.available) throw Object.assign(new Error(probe.message), { code: "tmux-monitor-unavailable" });
    if (providerSessionId !== null && !SAFE_SESSION.test(providerSessionId)) throw new Error("待恢复的 OpenCode session id 非法。");
    if (!Array.isArray(args) || args[0] !== "run" || !args.every(value => typeof value === "string")) throw new Error("OpenCode run 参数非法。");
    const socketName = this.socketName(audit.id);
    const auditStateRoot = join(this.stateRoot, audit.id);
    await mkdir(auditStateRoot, { recursive: true });
    await this.stop({ socket_name: socketName, target: "audit:tui" }).catch(() => {});

    const runSpecPath = join(auditStateRoot, "tmux-run.json");
    const outputPath = join(auditStateRoot, "opencode-run.jsonl");
    const exitPath = join(auditStateRoot, "opencode-run-exit.json");
    const relaySpecPath = join(auditStateRoot, "terminal-output-relay.json");
    await Promise.all([rm(outputPath, { force: true }), rm(exitPath, { force: true })]);
    await writeFile(runSpecPath, `${JSON.stringify({
      command: this.command,
      args,
      cwd: executionDirectory,
      environment: runtimeOverrides(environment),
      diagnostic_path: outputPath,
      exit_path: exitPath,
    }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await writeFile(relaySpecPath, `${JSON.stringify({ output_path: outputPath, exit_path: exitPath }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    try {
      const target = "audit:tui";
      await this.tmux(socketName, ["new-session", "-d", "-x", "160", "-y", "48", "-s", "audit", "-n", "tui", "-c", executionDirectory, "--", process.execPath, LAUNCHER, runSpecPath], { timeout: 30_000 });
      const terminal = {
        backend: this.multiplexerBackend ?? "tmux",
        transport: "opencode-run+terminal-multiplexer",
        supported: true,
        status: "ready",
        live: true,
        socket_name: socketName,
        target,
        provider_session_id: providerSessionId,
        output_path: outputPath,
        exit_path: exitPath,
        relay_spec_path: relaySpecPath,
        columns: 160,
        rows: 48,
        attach_command: `${this.multiplexerBackend === "psmux" ? "psmux" : "tmux"} -L ${socketName} attach-session -r -t ${target}`,
        opencode_command: providerSessionId ? `opencode -s ${providerSessionId}` : null,
        resumed: providerSessionId !== null,
        message: providerSessionId ? `OpenCode run 已续接原会话并在隔离 ${this.multiplexerBackend ?? "tmux"} 中运行。` : `OpenCode run 已在隔离 ${this.multiplexerBackend ?? "tmux"} 会话中运行。`,
      };
      const initialOutput = await this.initialRunOutput(terminal);
      const discoveredSessionId = providerSessionId ?? sessionFromOutput(initialOutput);
      if (discoveredSessionId) {
        terminal.provider_session_id = discoveredSessionId;
        terminal.opencode_command = `opencode -s ${discoveredSessionId}`;
      } else if (!initialOutput.trim()) {
        terminal.message = `OpenCode run 已在隔离 ${this.multiplexerBackend ?? "tmux"} 会话中启动，正在等待异步输出；这不会阻塞审计 Runner。`;
      }
      return terminal;
    } catch (error) {
      await this.stop({ socket_name: socketName, target: "audit:tui" }).catch(() => {});
      throw error;
    }
  }

  async capture(terminal, lines = 400) {
    this.validateMetadata(terminal);
    try {
      const result = await this.tmux(terminal.socket_name, ["capture-pane", "-p", "-J", "-S", `-${Math.min(Math.max(Number(lines) || 400, 20), 2000)}`, "-t", terminal.target]);
      return String(result.stdout ?? "").replaceAll("\u0000", "").replace(/[ \t]+$/gm, "").trimEnd();
    } catch (error) {
      if (!terminal.output_path) throw error;
      const output = String(await readFile(terminal.output_path, "utf8")).replaceAll("\u0000", "").replace(/[ \t]+$/gm, "").trimEnd();
      return output.split(/\r?\n/).slice(-Math.min(Math.max(Number(lines) || 400, 20), 2000)).join("\n");
    }
  }

  async abort(terminal) {
    this.validateMetadata(terminal);
    await this.tmux(terminal.socket_name, ["send-keys", "-t", terminal.target, "C-c"]);
    return true;
  }

  async signalRun(terminal, signal) {
    this.validateMetadata(terminal);
    if (!new Set(["SIGSTOP", "SIGCONT"]).has(signal)) throw new Error("不支持的 OpenCode run 信号。");
    const result = await this.tmux(terminal.socket_name, ["list-panes", "-t", terminal.target, "-F", "#{pane_pid}"]);
    const pid = Number(String(result.stdout ?? "").trim().split(/\s+/)[0]);
    if (!Number.isSafeInteger(pid) || pid <= 1) throw new Error("无法解析 OpenCode run pane PID。");
    try {
      process.kill(-pid, signal);
    } catch (error) {
      if (error?.code !== "ESRCH") throw error;
      process.kill(pid, signal);
    }
  }

  async stop(terminal) {
    if (!SAFE_SOCKET.test(terminal?.socket_name ?? "")) return;
    try {
      await this.tmux(terminal.socket_name, ["kill-server"]);
    } catch (error) {
      const detail = `${error?.stderr ?? ""} ${error?.message ?? ""}`;
      if (!/no server running|failed to connect|No such file/i.test(detail)) throw error;
    }
  }
}
