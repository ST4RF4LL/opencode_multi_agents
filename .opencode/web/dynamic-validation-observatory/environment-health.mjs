import { execFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { access, readFile } from "node:fs/promises";
import { arch, homedir, platform as osPlatform } from "node:os";
import { basename, delimiter, isAbsolute, join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const CACHE_TTL_MS = 30_000;
const VERSION_TIMEOUT_MS = 8_000;

function oneLine(value) {
  return String(value ?? "").split(/\r?\n/).map(line => line.trim()).find(Boolean)?.slice(0, 240) ?? null;
}

async function executablePath(command, environment, platform) {
  if (!command) return null;
  const suffixes = platform === "win32"
    ? (environment.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";").filter(Boolean)
    : [""];
  const explicit = isAbsolute(command) || command.includes("/") || command.includes("\\");
  const candidates = explicit
    ? [command]
    : (environment.PATH ?? "").split(delimiter).filter(Boolean).flatMap(directory => suffixes.map(suffix => join(directory, suffix && !command.toUpperCase().endsWith(suffix.toUpperCase()) ? `${command}${suffix}` : command)));
  for (const candidate of candidates) {
    try {
      await access(candidate, platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK);
      return candidate;
    } catch {
      // Continue searching PATH without exposing filesystem errors.
    }
  }
  return null;
}

async function probeExecutable({ id, label, category, command, args = ["--version"], requiredFor = [], environment, platform, execute, resolveCommand = executablePath }) {
  const resolved = await resolveCommand(command, environment, platform);
  if (!resolved) {
    return { id, label, category, status: "unavailable", version: null, command: basename(command || id), required_for: requiredFor, detail: "未找到可执行文件。" };
  }
  let version = null;
  let detail = "可执行文件已就绪。";
  if (args === null) return { id, label, category, status: "ready", version, command: basename(resolved), required_for: requiredFor, detail };
  try {
    const result = await execute(resolved, args, { encoding: "utf8", timeout: VERSION_TIMEOUT_MS, maxBuffer: 1024 * 1024, env: environment });
    version = oneLine(result.stdout) ?? oneLine(result.stderr);
  } catch (error) {
    version = oneLine(error.stdout) ?? oneLine(error.stderr);
    detail = version ? "可执行文件已就绪；版本命令返回非零状态。" : "可执行文件已就绪；未能读取版本信息。";
  }
  return { id, label, category, status: "ready", version, command: basename(resolved), required_for: requiredFor, detail };
}

async function readPackageComponent(projectRoot) {
  try {
    const manifest = JSON.parse(await readFile(join(projectRoot, ".opencode", "node_modules", "@modelcontextprotocol", "sdk", "package.json"), "utf8"));
    return { id: "project_dependencies", label: "项目 Node.js 依赖", category: "基础运行时", status: "ready", version: manifest.version ?? null, command: "npm ci --prefix .opencode", required_for: ["workbench", "static", "dynamic"], detail: "MCP SDK 等项目依赖已安装。" };
  } catch {
    return { id: "project_dependencies", label: "项目 Node.js 依赖", category: "基础运行时", status: "unavailable", version: null, command: "npm ci --prefix .opencode", required_for: ["workbench", "static", "dynamic"], detail: "依赖不完整，请执行 npm ci --prefix .opencode。" };
  }
}

async function inspectMcpConfiguration(configPaths) {
  const states = { coverage_ledger: false, chrome_devtools: false, valid_configs: 0, invalid_configs: 0 };
  for (const path of [...new Set(configPaths.filter(Boolean))]) {
    try {
      const config = JSON.parse(await readFile(path, "utf8"));
      states.valid_configs += 1;
      states.coverage_ledger ||= config.mcp?.coverage_ledger?.enabled === true && Array.isArray(config.mcp.coverage_ledger.command);
      states.chrome_devtools ||= config.mcp?.["chrome-devtools"]?.enabled === true && Array.isArray(config.mcp["chrome-devtools"].command);
    } catch {
      states.invalid_configs += 1;
    }
  }
  return states;
}

async function chromeComponent({ environment, platform, execute, resolveCommand }) {
  const commands = platform === "darwin"
    ? ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", join(homedir(), "Applications", "Google Chrome.app", "Contents", "MacOS", "Google Chrome")]
    : platform === "win32"
      ? [join(environment.PROGRAMFILES ?? "C:\\Program Files", "Google", "Chrome", "Application", "chrome.exe"), join(environment["PROGRAMFILES(X86)"] ?? "C:\\Program Files (x86)", "Google", "Chrome", "Application", "chrome.exe")]
      : ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"];
  for (const command of commands) {
    const result = await probeExecutable({ id: "chrome", label: "Google Chrome", category: "动态验证", command, requiredFor: ["dynamic"], environment, platform, execute, resolveCommand });
    if (result.status === "ready") return result;
  }
  return { id: "chrome", label: "Google Chrome", category: "动态验证", status: "unavailable", version: null, command: "google-chrome", required_for: ["dynamic"], detail: "未找到可见 Chrome；静态审计不受影响。" };
}

function configuredComponent(id, label, category, configured, requiredFor, detail) {
  return {
    id,
    label,
    category,
    status: configured ? "ready" : "unavailable",
    version: null,
    command: "opencode.json",
    required_for: requiredFor,
    detail: configured ? detail : "已登记仓库中未发现有效的启用配置。",
  };
}

function capability(id, label, componentIds, components, { anyOf = [] } = {}) {
  const byId = new Map(components.map(component => [component.id, component]));
  const missing = componentIds.filter(componentId => byId.get(componentId)?.status !== "ready");
  if (anyOf.length && !anyOf.some(componentId => byId.get(componentId)?.status === "ready")) missing.push(anyOf.join(" / "));
  return {
    id,
    label,
    status: missing.length ? "blocked" : "ready",
    blockers: [...new Set(missing)],
    summary: missing.length ? `缺少 ${[...new Set(missing)].length} 项必要能力。` : "必要组件均已就绪。",
  };
}

export class EnvironmentHealthService {
  constructor({ projectRoot, configPaths = [], environment = process.env, platform = osPlatform(), architecture = arch(), nodeVersion = process.versions.node, execute = execFileAsync, resolveCommand = executablePath, cacheTtlMs = CACHE_TTL_MS } = {}) {
    this.projectRoot = projectRoot;
    this.configPaths = configPaths;
    this.environment = environment;
    this.platform = platform;
    this.architecture = architecture;
    this.nodeVersion = nodeVersion;
    this.execute = execute;
    this.resolveCommand = resolveCommand;
    this.cacheTtlMs = cacheTtlMs;
    this.cached = null;
    this.pending = null;
  }

  async snapshot({ force = false } = {}) {
    if (!force && this.cached && Date.now() - this.cached.generated_at_ms < this.cacheTtlMs) return this.cached.value;
    if (!force && this.pending) return this.pending;
    this.pending = this.build().finally(() => { this.pending = null; });
    return this.pending;
  }

  async build() {
    const environment = this.environment;
    const platform = this.platform;
    const execute = this.execute;
    const resolveCommand = this.resolveCommand;
    const javaCommand = environment.JOERN_JAVA_BIN ? join(environment.JOERN_JAVA_BIN, platform === "win32" ? "java.exe" : "java") : environment.JAVA_HOME ? join(environment.JAVA_HOME, "bin", platform === "win32" ? "java.exe" : "java") : "java";
    const nodeMajor = Number(String(this.nodeVersion).split(".")[0]);
    const node = {
      id: "node", label: "Node.js", category: "基础运行时", status: nodeMajor >= 20 ? "ready" : "unavailable", version: this.nodeVersion,
      command: "node", required_for: ["workbench", "static", "dynamic"], detail: nodeMajor >= 20 ? "满足 Node.js 20+ 要求。" : "需要 Node.js 20 或更高版本。",
    };
    const [npm, git, opencode, tmux, java, joern, joernParse, opengrep, semgrep, chrome, dependencies, mcp] = await Promise.all([
      probeExecutable({ id: "npm", label: "npm", category: "基础运行时", command: platform === "win32" ? "npm.cmd" : "npm", requiredFor: ["workbench", "dynamic"], environment, platform, execute, resolveCommand }),
      probeExecutable({ id: "git", label: "Git", category: "基础运行时", command: "git", requiredFor: ["static", "dynamic"], environment, platform, execute, resolveCommand }),
      probeExecutable({ id: "opencode", label: "OpenCode CLI", category: "Agent 运行时", command: environment.OPENCODE_BIN ?? "opencode", requiredFor: ["static", "dynamic"], environment, platform, execute, resolveCommand }),
      probeExecutable({ id: "tmux", label: "tmux", category: "Agent 运行时", command: "tmux", requiredFor: ["terminal_monitor"], environment, platform, execute, resolveCommand }),
      probeExecutable({ id: "java", label: "Java", category: "静态分析", command: javaCommand, requiredFor: ["static"], environment, platform, execute, resolveCommand }),
      probeExecutable({ id: "joern", label: "Joern", category: "静态分析", command: environment.JOERN_BIN ?? "joern", args: null, requiredFor: ["static"], environment, platform, execute, resolveCommand }),
      probeExecutable({ id: "joern_parse", label: "joern-parse", category: "静态分析", command: environment.JOERN_PARSE_BIN ?? "joern-parse", args: ["--list-languages"], requiredFor: ["static"], environment, platform, execute, resolveCommand }),
      probeExecutable({ id: "opengrep", label: "OpenGrep", category: "静态分析", command: environment.OPENGREP_BIN ?? "opengrep", requiredFor: [], environment, platform, execute, resolveCommand }),
      probeExecutable({ id: "semgrep", label: "Semgrep", category: "静态分析", command: environment.SEMGREP_BIN ?? "semgrep", requiredFor: [], environment, platform, execute, resolveCommand }),
      chromeComponent({ environment, platform, execute, resolveCommand }),
      readPackageComponent(this.projectRoot),
      inspectMcpConfiguration(this.configPaths),
    ]);
    const coverage = configuredComponent("coverage_ledger", "Coverage Ledger MCP", "Agent 运行时", mcp.coverage_ledger, ["static"], "本地 Coverage Ledger MCP 已启用。" );
    const chromeMcp = configuredComponent("chrome_devtools_mcp", "Chrome DevTools MCP", "动态验证", mcp.chrome_devtools, ["dynamic"], "隔离 Chrome DevTools MCP 已启用。" );
    const components = [node, npm, dependencies, git, opencode, tmux, coverage, java, joern, joernParse, opengrep, semgrep, chrome, chromeMcp];
    const capabilities = [
      capability("workbench", "工作台", ["node", "project_dependencies"], components),
      capability("static", "静态漏洞挖掘", ["node", "git", "opencode", "project_dependencies", "coverage_ledger", "java", "joern", "joern_parse"], components, { anyOf: ["opengrep", "semgrep"] }),
      capability("terminal_monitor", "OpenCode 窗口监控", ["node", "opencode", "tmux"], components),
      capability("dynamic", "Web 动态验证", ["node", "npm", "git", "opencode", "project_dependencies", "chrome", "chrome_devtools_mcp"], components),
    ];
    const value = {
      generated_at: new Date().toISOString(),
      platform: { os: platform, arch: this.architecture, node: this.nodeVersion },
      configuration: { checked: this.configPaths.length, valid: mcp.valid_configs, invalid: mcp.invalid_configs },
      capabilities,
      components,
    };
    this.cached = { generated_at_ms: Date.now(), value };
    return value;
  }
}
