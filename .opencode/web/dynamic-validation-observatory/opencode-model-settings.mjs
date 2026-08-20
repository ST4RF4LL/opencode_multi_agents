import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

export const DEFAULT_MODEL_SELECTION = "default";

// OpenCode accepts provider/model.  Permit nested provider paths and the
// punctuation used by provider model IDs, but never let a persisted setting
// become an arbitrary CLI argument.
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._:@-]*)+$/;
const MODEL_PATH = /^[A-Za-z0-9][A-Za-z0-9._:@-]*(?:\/[A-Za-z0-9][A-Za-z0-9._:@-]*)*$/;
const SCHEMA_VERSION = 1;

function invalid(message, code = "opencode-model-settings-invalid") {
  return Object.assign(new Error(message), { statusCode: 422, code });
}

function modelId(value, provider = null) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  // `provider.models` uses model names relative to that provider.  Some model
  // IDs themselves contain `/`, so qualify before accepting a standalone ID.
  if (provider && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(provider) && MODEL_PATH.test(trimmed)) {
    const qualified = `${provider}/${trimmed}`;
    return MODEL_ID.test(qualified) ? qualified : null;
  }
  if (MODEL_ID.test(trimmed)) return trimmed;
  return null;
}

function addModel(models, value, provider = null) {
  const normalized = modelId(value, provider);
  if (normalized) models.add(normalized);
}

function addConfiguredModels(models, definition, provider = null) {
  if (typeof definition === "string") {
    addModel(models, definition, provider);
    return;
  }
  if (Array.isArray(definition)) {
    for (const item of definition) addConfiguredModels(models, item, provider);
    return;
  }
  if (!definition || typeof definition !== "object") return;
  addModel(models, definition.model, provider);
  addModel(models, definition.id, provider);
  if (Array.isArray(definition.models)) {
    for (const item of definition.models) addConfiguredModels(models, item, provider);
  } else if (definition.models && typeof definition.models === "object") {
    for (const [name, item] of Object.entries(definition.models)) {
      addModel(models, name, provider);
      addConfiguredModels(models, item, provider);
    }
  }
}

function modelsFromConfig(config) {
  const models = new Set();
  if (!config || typeof config !== "object" || Array.isArray(config)) return models;

  // Explicit defaults and per-agent defaults can name a provider/model even
  // when the provider model override uses no local `models` block.
  for (const key of ["model", "small_model"]) addModel(models, config[key]);
  for (const agents of [config.agent, config.agents]) {
    if (!agents || typeof agents !== "object" || Array.isArray(agents)) continue;
    for (const definition of Object.values(agents)) addConfiguredModels(models, definition);
  }

  for (const providers of [config.provider, config.providers]) {
    if (!providers || typeof providers !== "object" || Array.isArray(providers)) continue;
    for (const [provider, definition] of Object.entries(providers)) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(provider)) continue;
      addConfiguredModels(models, definition, provider);
    }
  }

  // Keep this compatibility path for configurations that expose a top-level
  // model collection instead of nesting it below a provider.
  if (Array.isArray(config.models)) {
    for (const item of config.models) addConfiguredModels(models, item);
  } else if (config.models && typeof config.models === "object") {
    for (const [name, definition] of Object.entries(config.models)) {
      addModel(models, name);
      addConfiguredModels(models, definition, typeof definition?.provider === "string" ? definition.provider : null);
    }
  }
  return models;
}

export function normalizeOpenCodeModel(value, { allowDefault = true } = {}) {
  if (value === undefined || value === null || (allowDefault && value === DEFAULT_MODEL_SELECTION)) return null;
  const normalized = modelId(value);
  if (!normalized) throw invalid("模型必须采用 provider/model 格式。", "opencode-model-invalid");
  return normalized;
}

export class OpenCodeModelCatalog {
  constructor({ configPaths = [] } = {}) {
    this.configPaths = [...new Set(configPaths.filter(path => typeof path === "string" && path.trim()).map(path => resolve(path)))];
  }

  async snapshot() {
    const models = new Set();
    const sources = [];
    for (const path of this.configPaths) {
      try {
        const config = JSON.parse(await readFile(path, "utf8"));
        if (!config || typeof config !== "object" || Array.isArray(config)) {
          sources.push({ path, status: "invalid", model_count: 0, message: "配置根必须是 JSON 对象。" });
          continue;
        }
        const configured = modelsFromConfig(config);
        for (const model of configured) models.add(model);
        sources.push({ path, status: "ready", model_count: configured.size, message: null });
      } catch (error) {
        if (error?.code === "ENOENT") sources.push({ path, status: "missing", model_count: 0, message: null });
        else sources.push({ path, status: "invalid", model_count: 0, message: "配置不是有效 JSON。" });
      }
    }
    return { models: [...models].sort((left, right) => left.localeCompare(right)), sources };
  }
}

function normalizeDocument(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw invalid("模型设置文件不是有效 JSON 对象。");
  if (value.schema_version !== undefined && value.schema_version !== SCHEMA_VERSION) {
    throw invalid(`不支持的模型设置版本：${value.schema_version}。`, "opencode-model-settings-version-invalid");
  }
  return {
    schema_version: SCHEMA_VERSION,
    model: normalizeOpenCodeModel(value.model ?? value.selected_model),
    updated_at: typeof value.updated_at === "string" ? value.updated_at : null,
  };
}

export class OpenCodeModelSettingsStore {
  constructor({ path, clock = () => Date.now() } = {}) {
    if (!path) throw new Error("模型设置路径不能为空。");
    this.path = resolve(path);
    this.clock = clock;
    this.document = null;
    this.writes = Promise.resolve();
    this.ready = this.initialize();
  }

  async initialize() {
    await mkdir(dirname(this.path), { recursive: true });
    try {
      this.document = normalizeDocument(JSON.parse(await readFile(this.path, "utf8")));
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      this.document = { schema_version: SCHEMA_VERSION, model: null, updated_at: null };
      await this.persist();
    }
  }

  async persist() {
    const temporary = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temporary, `${JSON.stringify(this.document, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, this.path);
  }

  async get() {
    await this.ready;
    return structuredClone(this.document);
  }

  async update(value, availableModels = []) {
    const model = normalizeOpenCodeModel(value);
    if (model && !new Set(availableModels).has(model)) {
      throw invalid("所选模型不在当前 OpenCode 配置清单中。", "opencode-model-not-configured");
    }
    await this.ready;
    const operation = this.writes.catch(() => {}).then(async () => {
      this.document = {
        schema_version: SCHEMA_VERSION,
        model,
        updated_at: new Date(this.clock()).toISOString(),
      };
      await this.persist();
      return structuredClone(this.document);
    });
    this.writes = operation;
    return operation;
  }
}
