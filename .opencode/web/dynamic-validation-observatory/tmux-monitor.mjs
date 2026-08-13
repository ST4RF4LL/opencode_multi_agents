import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const LAUNCHER = fileURLToPath(new URL("./tmux-launcher.mjs", import.meta.url));
const SAFE_SOCKET = /^owa-[a-f0-9]{16}$/;
const SAFE_TARGET = /^audit:(?:server|tui)$/;
const SAFE_SESSION = /^[A-Za-z0-9._:-]{3,240}$/;
const MIN_COLUMNS = 40;
const MAX_COLUMNS = 320;
const MIN_ROWS = 12;
const MAX_ROWS = 120;

function localPort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : null;
      server.close(error => error ? reject(error) : resolve(port));
    });
  });
}

function runtimeOverrides(environment) {
  return Object.fromEntries(Object.entries(environment).filter(([key, value]) => (key.startsWith("OPENCODE_") || /^AUDIT_(?:SOURCE|ENGINE|WORKSPACE|REPORTS|TMP)_ROOT$/.test(key)) && typeof value === "string"));
}

async function fetchJson(url, options = {}, timeoutMs = 5_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal, headers: { Accept: "application/json", ...(options.headers ?? {}) } });
    const text = await response.text();
    if (!response.ok) throw new Error(`HTTP ${response.status}${text.trim() ? `: ${text.trim().slice(0, 500)}` : ""}`);
    return text.trim() ? JSON.parse(text) : null;
  } finally {
    clearTimeout(timer);
  }
}

export class OpenCodeTmuxMonitor {
  constructor({ stateRoot, command = "opencode", tmuxCommand = "tmux", execute = execFileAsync, readyTimeoutMs = 30_000 } = {}) {
    this.stateRoot = stateRoot;
    this.command = command;
    this.tmuxCommand = tmuxCommand;
    this.execute = execute;
    this.readyTimeoutMs = readyTimeoutMs;
    this.probeResult = null;
  }

  socketName(auditId) {
    return `owa-${createHash("sha256").update(`${this.stateRoot}\u0000${auditId}`).digest("hex").slice(0, 16)}`;
  }

  async probe({ force = false } = {}) {
    if (this.probeResult && !force) return this.probeResult;
    try {
      const [tmux, attach] = await Promise.all([
        this.execute(this.tmuxCommand, ["-V"], { encoding: "utf8", timeout: 5_000, maxBuffer: 1024 * 1024 }),
        this.execute(this.command, ["attach", "--help"], { encoding: "utf8", timeout: 10_000, maxBuffer: 1024 * 1024 }),
      ]);
      const help = `${attach.stdout ?? ""}\n${attach.stderr ?? ""}`;
      const missing = ["--dir", "--session", "--mini"].filter(flag => !help.includes(flag));
      if (missing.length) throw new Error(`OpenCode attach 缺少 ${missing.join("、")}`);
      this.probeResult = { available: true, tmux_version: String(tmux.stdout || tmux.stderr || "").trim(), message: "tmux 与 OpenCode attach 已就绪。" };
    } catch (error) {
      this.probeResult = { available: false, tmux_version: null, message: `tmux 监控不可用：${error.message}` };
    }
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

  async waitForServer(serverUrl) {
    const deadline = Date.now() + this.readyTimeoutMs;
    let detail = "";
    while (Date.now() < deadline) {
      try {
        await fetchJson(`${serverUrl}/global/health`, {}, 1_000);
        return;
      } catch (error) {
        detail = error.message;
      }
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    throw new Error(`OpenCode server 未在超时内就绪：${detail}`);
  }

  async waitForTui(socketName, target) {
    const deadline = Date.now() + Math.min(this.readyTimeoutMs, 10_000);
    let detail = "";
    while (Date.now() < deadline) {
      try {
        const output = await this.capture({ socket_name: socketName, target });
        if (output.trim()) return output;
      } catch (error) {
        detail = error.message;
      }
      await new Promise(resolve => setTimeout(resolve, 150));
    }
    throw new Error(`OpenCode TUI 未在超时内生成画面：${detail}`);
  }

  async start({ audit, repository, environment, executionDirectory = repository.path, providerSessionId = null }) {
    const probe = await this.probe();
    if (!probe.available) throw Object.assign(new Error(probe.message), { code: "tmux-monitor-unavailable" });
    if (providerSessionId !== null && !SAFE_SESSION.test(providerSessionId)) throw new Error("待恢复的 OpenCode session id 非法。");
    const socketName = this.socketName(audit.id);
    const auditStateRoot = join(this.stateRoot, audit.id);
    const serverUrl = `http://127.0.0.1:${await localPort()}`;
    await mkdir(auditStateRoot, { recursive: true });
    await this.stop({ socket_name: socketName, target: "audit:server" }).catch(() => {});

    const serverSpecPath = join(auditStateRoot, "tmux-server.json");
    await writeFile(serverSpecPath, `${JSON.stringify({
      command: this.command,
      args: ["serve", "--hostname", "127.0.0.1", "--port", new URL(serverUrl).port],
      cwd: executionDirectory,
      environment: runtimeOverrides(environment),
    }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await this.tmux(socketName, ["new-session", "-d", "-x", "160", "-y", "48", "-s", "audit", "-n", "server", "-c", executionDirectory, process.execPath, LAUNCHER, serverSpecPath], { timeout: 30_000 });
    try {
      await this.waitForServer(serverUrl);
      const query = new URLSearchParams({ directory: executionDirectory });
      const session = providerSessionId
        ? { id: providerSessionId, resumed: true }
        : await fetchJson(`${serverUrl}/session?${query}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ title: audit.name }),
          });
      if (!SAFE_SESSION.test(session?.id ?? "")) throw new Error("OpenCode session 响应缺少有效 id。");
      const target = "audit:tui";
      const attachSpecPath = join(auditStateRoot, "tmux-tui.json");
      await writeFile(attachSpecPath, `${JSON.stringify({
        command: this.command,
        args: ["attach", serverUrl, "--dir", executionDirectory, "--session", session.id, "--mini"],
        cwd: executionDirectory,
        environment: runtimeOverrides(environment),
      }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
      await this.tmux(socketName, ["new-window", "-d", "-t", "audit", "-n", "tui", "-c", executionDirectory, process.execPath, LAUNCHER, attachSpecPath]);
      await this.waitForTui(socketName, target);
      return {
        backend: "tmux",
        transport: "opencode-serve+prompt-api",
        supported: true,
        status: "ready",
        live: true,
        socket_name: socketName,
        target,
        server_url: serverUrl,
        provider_session_id: session.id,
        columns: 160,
        rows: 48,
        attach_command: `tmux -L ${socketName} attach-session -r -t ${target}`,
        opencode_command: `opencode -s ${session.id}`,
        resumed: session.resumed === true,
        message: session.resumed === true ? "OpenCode TUI 已续接原会话并在隔离 tmux 中运行。" : "OpenCode TUI 已在隔离 tmux 会话中运行。",
      };
    } catch (error) {
      await this.stop({ socket_name: socketName, target: "audit:server" }).catch(() => {});
      throw error;
    }
  }

  async capture(terminal, lines = 400) {
    this.validateMetadata(terminal);
    const result = await this.tmux(terminal.socket_name, ["capture-pane", "-p", "-J", "-S", `-${Math.min(Math.max(Number(lines) || 400, 20), 2000)}`, "-t", terminal.target]);
    return String(result.stdout ?? "").replaceAll("\u0000", "").replace(/[ \t]+$/gm, "").trimEnd();
  }

  async abort(terminal, directory) {
    if (!terminal?.server_url || !terminal?.provider_session_id) return false;
    const query = new URLSearchParams({ directory });
    await fetchJson(`${terminal.server_url}/session/${encodeURIComponent(terminal.provider_session_id)}/abort?${query}`, { method: "POST" });
    return true;
  }

  async signalServer(terminal, signal) {
    this.validateMetadata({ ...terminal, target: "audit:server" });
    if (!new Set(["SIGSTOP", "SIGCONT"]).has(signal)) throw new Error("不支持的 OpenCode server 信号。");
    const result = await this.tmux(terminal.socket_name, ["list-panes", "-t", "audit:server", "-F", "#{pane_pid}"]);
    const pid = Number(String(result.stdout ?? "").trim().split(/\s+/)[0]);
    if (!Number.isSafeInteger(pid) || pid <= 1) throw new Error("无法解析 OpenCode server pane PID。");
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
