import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";

function commandPath(value, engineRoot) {
  if (typeof value !== "string" || isAbsolute(value)) return value;
  if (!value.startsWith("./") && !value.startsWith("../") && !value.startsWith(".opencode/") && !value.startsWith(".opencode\\")) return value;
  return resolve(engineRoot, value);
}

export async function buildOpenCodeEnvironment(configPath, baseEnvironment = process.env) {
  const absoluteConfigPath = resolve(configPath);
  const configDirectory = dirname(absoluteConfigPath);
  const engineRoot = resolve(configDirectory, "..");
  const config = JSON.parse(await readFile(absoluteConfigPath, "utf8"));
  const mcp = {};
  for (const [id, definition] of Object.entries(config.mcp ?? {})) {
    if (!definition || definition.type !== "local" || !Array.isArray(definition.command)) continue;
    mcp[id] = {
      ...definition,
      command: definition.command.map(value => commandPath(value, engineRoot)),
    };
  }
  return {
    ...baseEnvironment,
    OPENCODE_CONFIG: absoluteConfigPath,
    OPENCODE_CONFIG_DIR: configDirectory,
    OPENCODE_CONFIG_CONTENT: JSON.stringify({ mcp }),
    OPENCODE_DISABLE_PROJECT_CONFIG: "true",
  };
}
