import { isAbsolute, relative, resolve, sep } from "node:path";

export function reportArtifactPath(workspaceRoot, value, prefix = "reports/") {
  if (typeof value !== "string" || !value) throw new Error("制品路径不能为空。");
  const absolute = isAbsolute(value) ? resolve(value) : resolve(workspaceRoot, value);
  // Web workspaces link reports/ to an injected durable root. Accept both
  // spellings, but preserve the logical reports/ path in artifact references.
  const roots = [resolve(workspaceRoot, "reports"), ...(process.env.AUDIT_REPORTS_ROOT ? [resolve(process.env.AUDIT_REPORTS_ROOT)] : [])];
  for (const root of roots) {
    const suffix = relative(root, absolute).split(sep).join("/");
    if (!suffix || suffix === ".." || suffix.startsWith("../") || isAbsolute(suffix)) continue;
    const logical = `reports/${suffix}`;
    if (logical.startsWith(prefix)) return { absolute, relative: logical };
  }
  throw new Error(`路径不在 ${prefix} 下：${value}`);
}
