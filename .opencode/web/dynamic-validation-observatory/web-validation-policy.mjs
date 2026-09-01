import { readFile } from "node:fs/promises";

const CATALOG_URL = new URL("../../shared/security-audit/catalogs/application-ai-vulnerability-catalog.json", import.meta.url);
let capabilityPromise;

async function capabilities() {
  if (!capabilityPromise) {
    capabilityPromise = readFile(CATALOG_URL, "utf8").then(source => {
      const catalog = JSON.parse(source);
      return new Map((catalog.entries ?? [])
        .filter(entry => Array.isArray(entry.applies_to) && entry.applies_to.includes("web"))
        .map(entry => [entry.id, {
          vulnerability_type_id: entry.id,
          title: entry.title,
          validator: entry.id === "JW-INJECT-06" ? "web-xss" : "web-generic",
        }]));
    });
  }
  return capabilityPromise;
}

export async function webValidationCapability(vulnerabilityTypeId) {
  return (await capabilities()).get(vulnerabilityTypeId) ?? null;
}

export async function isWebValidationType(vulnerabilityTypeId) {
  return Boolean(await webValidationCapability(vulnerabilityTypeId));
}

export async function webValidationTypes() {
  return [...(await capabilities()).values()].map(value => ({ ...value }));
}
