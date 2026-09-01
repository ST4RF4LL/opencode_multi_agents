import { randomUUID } from "node:crypto";
import { platform as osPlatform } from "node:os";

export const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
export const BROWSER_MODES = new Set(["auto", "shared_tab", "isolated_context", "isolated_browser"]);

function issue(code, message) {
  return { code, message };
}

export function loopbackUrl(value) {
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol) || !LOOPBACK_HOSTS.has(url.hostname) || url.username || url.password) return null;
    return url;
  } catch {
    return null;
  }
}

export function authorizeDynamicTask(spec = {}, { requireAccounts = false } = {}) {
  const issues = [];
  if (spec.enabled !== true || spec.explicit_authorization !== true) {
    issues.push(issue("dynamic-validation-not-explicitly-enabled", "动态验证未被显式启用和授权。"));
  }
  if (spec.test_environment !== true) issues.push(issue("test-environment-not-confirmed", "没有确认专用测试环境。"));
  const target = loopbackUrl(spec.target_base_url);
  if (!target) issues.push(issue("target-not-loopback", "授权目标不是有效的 loopback HTTP(S) URL。"));
  const requestedMode = spec.browser_mode ?? "auto";
  if (!BROWSER_MODES.has(requestedMode)) issues.push(issue("browser-mode-invalid", "浏览器模式无效。"));
  if (requireAccounts) {
    const attacker = spec.accounts?.attacker;
    const victim = spec.accounts?.victim;
    if (!attacker?.username || !attacker?.password || !victim?.username || !victim?.password) {
      issues.push(issue("test-accounts-missing", "动态验证所需测试账号不完整。"));
    } else if (attacker.username === victim.username) {
      issues.push(issue("test-accounts-not-distinct", "攻击者与受害者测试账号必须不同。"));
    }
  }
  if (issues.length) return { status: "SKIPPED", authorized: false, issues, target: null };
  return {
    status: "AUTHORIZED",
    authorized: true,
    issues: [],
    target: { url: target.href, origin: target.origin, hostname: target.hostname },
  };
}

export function chooseBrowserMode({ requested = "auto", platform = osPlatform(), desktopAvailable = true, riskSignals = [] } = {}) {
  if (!BROWSER_MODES.has(requested)) throw Object.assign(new Error("浏览器模式无效。"), { code: "browser-mode-invalid" });
  const isolationSignals = new Set(["distinct_accounts", "stored_xss", "downloads", "permissions", "service_worker", "proxy", "custom_certificate", "persistent_mutation", "clean_state"]);
  const requiresIsolation = riskSignals.some(signal => isolationSignals.has(signal));
  if (requested === "isolated_browser") return { mode: "isolated_browser", headless: platform === "linux" && !desktopAvailable, escalated: false, reason: "explicit" };
  if (requiresIsolation || (platform === "linux" && !desktopAvailable)) {
    return { mode: "isolated_browser", headless: platform === "linux" && !desktopAvailable, escalated: requested !== "isolated_browser", reason: requiresIsolation ? "risk-policy" : "headless-server" };
  }
  if (requested === "isolated_context") return { mode: "isolated_context", headless: false, escalated: false, reason: "explicit" };
  if (requested === "shared_tab") return { mode: "shared_tab", headless: false, escalated: false, reason: "explicit" };
  return { mode: "shared_tab", headless: false, escalated: false, reason: "low-risk-default" };
}

export function sharedChromeReadiness({ chromeMajorVersion = null, remoteDebuggingEnabled = false, profileConnectionConfirmed = false } = {}) {
  const issues = [];
  const major = Number(chromeMajorVersion);
  if (!Number.isInteger(major) || major < 144) issues.push(issue("shared-chrome-version-unsupported", "共享标签页要求 Chrome 144 或更高版本。"));
  if (remoteDebuggingEnabled !== true) issues.push(issue("shared-chrome-remote-debugging-disabled", "共享标签页要求用户先为所选 Chrome profile 开启远程调试。"));
  if (profileConnectionConfirmed !== true) issues.push(issue("shared-chrome-profile-not-confirmed", "连接会让控制器看到所选 profile 的其他页面，必须由用户明确确认。"));
  return {
    ready: issues.length === 0,
    issues,
    warning: "共享 Chrome 连接可见所选 profile 的其他页面；控制器只能操作和关闭本任务登记的标签页。",
  };
}

export function chromeDevtoolsMcpDefinition(session, { packageSpec = "chrome-devtools-mcp@1.8.0", platform = osPlatform() } = {}) {
  const command = platform === "win32" ? "npx.cmd" : "npx";
  const args = ["-y", packageSpec, "--redact-network-headers=true", "--no-usage-statistics", "--no-performance-crux"];
  if (session.mode === "isolated_browser") {
    args.push("--isolated=true");
    if (session.headless) args.push("--headless=true");
  } else {
    args.push("--auto-connect");
  }
  return { type: "local", command: [command, ...args], cwd: ".", timeout: 300000, enabled: true };
}

export class BrowserSessionBroker {
  constructor({ platform = osPlatform(), desktopAvailable = platform !== "linux" || Boolean(process.env.DISPLAY || process.env.WAYLAND_DISPLAY), packageSpec = process.env.CHROME_DEVTOOLS_MCP_PACKAGE ?? "chrome-devtools-mcp@1.8.0", controller = null } = {}) {
    this.platform = platform;
    this.desktopAvailable = desktopAvailable;
    this.packageSpec = packageSpec;
    this.controller = controller;
    this.sessions = new Map();
  }

  create({ requested = "auto", riskSignals = [], chromeMajorVersion = null, remoteDebuggingEnabled = false, profileConnectionConfirmed = false } = {}) {
    const decision = chooseBrowserMode({ requested, platform: this.platform, desktopAvailable: this.desktopAvailable, riskSignals });
    const sharedReadiness = decision.mode === "shared_tab"
      ? sharedChromeReadiness({ chromeMajorVersion, remoteDebuggingEnabled, profileConnectionConfirmed })
      : null;
    if (sharedReadiness && !sharedReadiness.ready) {
      throw Object.assign(new Error(sharedReadiness.issues.map(item => item.message).join("；")), {
        code: "shared-chrome-not-ready",
        issues: sharedReadiness.issues,
      });
    }
    const session = {
      id: `browser_${randomUUID()}`,
      ...decision,
      context_name: decision.mode === "isolated_context" ? `dynval-${randomUUID()}` : null,
      owned_pages: [],
      created_at: new Date().toISOString(),
      status: "allocated",
      connection_warning: sharedReadiness?.warning ?? null,
      profile_connection_confirmed: decision.mode === "shared_tab" ? true : null,
    };
    session.mcp = chromeDevtoolsMcpDefinition(session, { packageSpec: this.packageSpec, platform: this.platform });
    this.sessions.set(session.id, session);
    return structuredClone(session);
  }

  registerPage(sessionId, pageId) {
    const session = this.sessions.get(sessionId);
    if (!session) throw Object.assign(new Error("浏览器会话不存在。"), { code: "browser-session-not-found" });
    if (!session.owned_pages.includes(pageId)) session.owned_pages.push(pageId);
    session.status = "active";
    return structuredClone(session);
  }

  async close(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    const failures = [];
    if (this.controller) {
      for (const pageId of [...session.owned_pages].reverse()) {
        try { await this.controller.closePage?.(pageId); }
        catch (error) { failures.push({ resource_type: "page", resource_id: String(pageId), message: error?.message ?? "close failed" }); }
      }
      if (session.context_name) {
        try { await this.controller.closeContext?.(session.context_name); }
        catch (error) { failures.push({ resource_type: "context", resource_id: session.context_name, message: error?.message ?? "close failed" }); }
      }
      if (session.mode === "isolated_browser") {
        try { await this.controller.closeBrowser?.(session.id); }
        catch (error) { failures.push({ resource_type: "browser", resource_id: session.id, message: error?.message ?? "close failed" }); }
      }
    }
    session.status = failures.length ? "cleanup_failed" : "closed";
    session.cleanup_failures = failures;
    session.closed_at = new Date().toISOString();
    if (failures.length) {
      throw Object.assign(new Error("部分受管浏览器资源未能关闭；禁止使用全局 Chrome 进程终止作为回退。"), {
        code: "browser-session-cleanup-failed",
        failures: structuredClone(failures),
      });
    }
    return true;
  }

  get(sessionId) {
    const session = this.sessions.get(sessionId);
    return session ? structuredClone(session) : null;
  }
}
