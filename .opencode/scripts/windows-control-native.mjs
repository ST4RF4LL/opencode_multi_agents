import { execFile } from "node:child_process";
import { createReadStream } from "node:fs";
import { lstat, mkdir, open, readFile, realpath, unlink } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import { controlError, localExePath, parseWinappJson } from "./windows-control-core.mjs";

const GUARD_SCRIPT = fileURLToPath(new URL("./windows-control-guard.ps1", import.meta.url));
const MAX_BYTES = 1024 * 1024;

export function executeFile(command, args, { timeout = 8000, exec = execFile } = {}) {
  return new Promise((resolve, reject) => {
    exec(command, args, { shell: false, windowsHide: true, encoding: "utf8", timeout,
      maxBuffer: MAX_BYTES, killSignal: "SIGTERM" }, (error, stdout, stderr) => {
      // Do not expose argv, output or exception messages from native processes.
      if (error) { reject(controlError(error.killed ? "CLI_TIMEOUT" : "CLI_PROCESS_FAILED")); return; }
      if (stderr?.trim()) { reject(controlError("CLI_STDERR_PRESENT")); return; }
      resolve(stdout);
    });
  });
}

async function fixedLocalFile(path) {
  const absolute = win32.normalize(path);
  const root = win32.parse(absolute).root;
  let current = root;
  for (const part of absolute.slice(root.length).split("\\")) {
    current = win32.join(current, part);
    if ((await lstat(current)).isSymbolicLink()) throw controlError("REPARSE_PATH_FORBIDDEN");
  }
  if ((await realpath(absolute)).toLowerCase() !== absolute.toLowerCase()) throw controlError("REALPATH_MISMATCH");
  if (!(await lstat(absolute)).isFile()) throw controlError("EXECUTABLE_FILE_REQUIRED");
}

async function hashFile(path) {
  const hash = createHash("sha256");
  let size = 0;
  for await (const chunk of createReadStream(path)) {
    size += chunk.length;
    if (size > 512 * 1024 * 1024) throw controlError("EXECUTABLE_SIZE_LIMIT");
    hash.update(chunk);
  }
  return hash.digest("hex");
}

export async function acquireDesktopLease(windowsSessionId, { directory = join(tmpdir(), "opencode-winapp-desktop-leases-v1"), task_id = null, binding_digest = null } = {}) {
  // The CLI never accepts a caller-selected lease root. A crashed/dirty lease is manual-only recovery.
  await mkdir(directory, { recursive: true, mode: 0o700 });
  if ((await lstat(directory)).isSymbolicLink()) throw controlError("LEASE_PATH_INVALID");
  const file = join(directory, `session-${windowsSessionId}.lock`);
  const token = randomUUID();
  let handle;
  try { handle = await open(file, "wx", 0o600); }
  catch (error) { throw controlError(error.code === "EEXIST" ? "DESKTOP_BUSY_OR_DIRTY" : "LEASE_FAILED"); }
  try { await handle.writeFile(JSON.stringify({ token, task_id, binding_digest, controller_pid: process.pid, created_at: new Date().toISOString() })); }
  finally { await handle.close(); }
  return async () => {
    try {
      const existing = JSON.parse(await readFile(file, "utf8"));
      if (existing.token !== token || (await lstat(file)).isSymbolicLink()) throw controlError("LEASE_OWNERSHIP_LOST");
      await unlink(file);
    } catch { throw controlError("LEASE_RELEASE_FAILED"); }
  };
}

export function createWindowsNative({ platform = process.platform, environment = process.env } = {}) {
  const ensureWindows = () => { if (platform !== "win32") throw controlError("WINDOWS_HOST_REQUIRED"); };
  const powershell = () => {
    ensureWindows();
    const root = environment.SystemRoot ?? environment.SYSTEMROOT;
    if (!root || !/^[A-Za-z]:\\Windows$/i.test(root)) throw controlError("WINDOWS_SYSTEM_ROOT_INVALID");
    return win32.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  };
  const guardCall = async args => parseWinappJson(await executeFile(powershell(), ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", GUARD_SCRIPT, ...args]));
  return {
    async acquire(sessionId, binding) { ensureWindows(); return acquireDesktopLease(sessionId, binding); },
    async execute(command, args) { ensureWindows(); return executeFile(localExePath(command), args); },
    async checkFiles(spec) {
      ensureWindows();
      // Reject mapped/network drives before opening or hashing any executable.
      const result = await guardCall(["-Mode", "Paths", "-ExePath", spec.target.exe_path, "-ToolPath", spec.tool.path]);
      if (result.local_fixed_drives !== true) throw controlError("LOCAL_FIXED_DRIVE_REQUIRED");
      for (const [path, expected] of [[spec.target.exe_path, spec.target.exe_sha256], [spec.tool.path, spec.tool.sha256]]) {
        await fixedLocalFile(localExePath(path));
        if (await hashFile(path) !== expected) throw controlError("EXECUTABLE_HASH_MISMATCH");
      }
    },
    async guard(target, automationId = null) {
      ensureWindows();
      const args = ["-Mode", "Target", "-TargetPid", String(target.pid), "-WindowHandle", target.hwnd,
        "-StartTimeTicks", target.start_time_ticks, "-SessionId", String(target.windows_session_id), "-ExePath", target.exe_path];
      if (automationId) args.push("-AutomationId", automationId);
      const value = await guardCall(args);
      if (value.valid !== true) throw controlError("TARGET_GUARD_FAILED");
      return value;
    },
  };
}

export async function readControlSpec(path) {
  if (!path) return null;
  if (typeof path !== "string" || /^(?:\\\\|\/\/)/.test(path) || path.includes("\0")) throw controlError("SPEC_FILE_INVALID");
  const info = await lstat(path);
  if (info.isSymbolicLink() || !info.isFile() || info.size > 64 * 1024) throw controlError("SPEC_FILE_INVALID");
  try { return JSON.parse(await readFile(path, "utf8")); }
  catch { throw controlError("SPEC_FILE_INVALID"); }
}
