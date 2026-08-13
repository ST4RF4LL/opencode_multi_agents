import { constants as fsConstants } from "node:fs";
import { access } from "node:fs/promises";
import { arch as osArch, platform as osPlatform } from "node:os";
import { delimiter, dirname, extname, isAbsolute, join, win32 } from "node:path";

export async function resolveExecutablePath(command, environment = process.env, platform = osPlatform()) {
  if (!command) return null;
  const suffixes = platform === "win32"
    ? (environment.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";").filter(Boolean)
    : [""];
  const explicit = isAbsolute(command) || command.includes("/") || command.includes("\\");
  const joinPath = platform === "win32" ? win32.join : join;
  const pathDelimiter = platform === "win32" ? ";" : delimiter;
  const candidates = explicit
    ? [command]
    : (environment.PATH ?? environment.Path ?? "").split(pathDelimiter).filter(Boolean).flatMap(directory => suffixes.map(suffix => (
        suffix && !command.toUpperCase().endsWith(suffix.toUpperCase()) ? joinPath(directory, `${command}${suffix}`) : joinPath(directory, command)
      )));
  for (const candidate of [...new Set(candidates)]) {
    try {
      await access(candidate, platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK);
      return candidate;
    } catch {
      // Continue searching without exposing host filesystem details.
    }
  }
  return null;
}

async function existingFile(path, platform) {
  try {
    await access(path, platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK);
    return path;
  } catch {
    return null;
  }
}

export async function resolvedOpenCodeExecutables({ command = null, environment = process.env, platform = osPlatform(), architecture = osArch(), resolveCommand = resolveExecutablePath } = {}) {
  const requested = [environment.OPENCODE_BIN_PATH, environment.OPENCODE_BIN, command, platform === "win32" ? "opencode.exe" : "opencode", "opencode"];
  const values = [];
  for (const candidate of [...new Set(requested.filter(Boolean))]) {
    const resolved = await resolveCommand(candidate, environment, platform);
    if (!resolved) continue;
    if (platform !== "win32") {
      values.push(resolved);
      continue;
    }
    const extension = extname(resolved).toLowerCase();
    if (extension === ".exe" || extension === ".com") values.push(resolved);
    const root = dirname(resolved);
    const packageRoot = win32.join(root, "node_modules", "opencode-ai");
    const platformPackage = `opencode-windows-${architecture}`;
    const packaged = [
      win32.join(packageRoot, "bin", "opencode.exe"),
      win32.join(packageRoot, "node_modules", platformPackage, "bin", "opencode.exe"),
      win32.join(packageRoot, "node_modules", `${platformPackage}-baseline`, "bin", "opencode.exe"),
    ];
    for (const path of packaged) {
      const found = await existingFile(path, platform);
      if (found) values.push(found);
    }
  }
  return [...new Set(values)];
}
