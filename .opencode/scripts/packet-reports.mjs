import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

export const PACKET_REPORT_CONTRACT = "tri-lens-v2";
export const PACKET_LENSES = ["sink-driven", "control-driven", "config-driven"];
const digest = bytes => createHash("sha256").update(bytes).digest("hex");
const inside = (root, path) => { const rel = relative(root, path); return rel && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel); };

export function itemReportPaths(item) {
  return item.report_contract === PACKET_REPORT_CONTRACT
    ? (item.report_bindings ?? []).map(binding => binding.path)
    : (typeof item.artifact_path === "string" ? [item.artifact_path] : []);
}

export async function validatePacketReports({ reportsRoot, auditId, item, reports }) {
  if (!Array.isArray(reports) || reports.length !== 3 || new Set(reports.map(entry => entry.lens)).size !== 3
    || reports.some(entry => !PACKET_LENSES.includes(entry.lens))) throw new Error("工作包必须绑定三个不同视角的报告。");
  const root = resolve(reportsRoot), realRoot = await realpath(root);
  const seenPaths = new Set(), sessions = new Set(), findings = new Set();
  for (const binding of reports) {
    if (typeof binding.path !== "string" || isAbsolute(binding.path) || !/^[a-f0-9]{64}$/.test(binding.sha256 ?? "")) throw new Error("视角报告路径或摘要无效。");
    const path = resolve(root, binding.path);
    if (!inside(root, path) || seenPaths.has(path)) throw new Error("视角报告路径越界或重复。");
    seenPaths.add(path);
    const info = await lstat(path);
    if (!info.isFile() || info.isSymbolicLink() || !inside(realRoot, await realpath(path))) throw new Error("视角报告不是受控普通文件。");
    const bytes = await readFile(path);
    if (digest(bytes) !== binding.sha256) throw new Error("视角报告摘要不匹配。");
    const report = JSON.parse(bytes.toString("utf8"));
    if (report.audit_id !== auditId || report.focus_area_id !== item.focus_area_id || report.agent_name !== item.agent_name
      || report.audit_strategy !== binding.lens || report.discovery_track !== "coverage"
      || (item.scope_digest && (report.scope_digest ?? report.scope?.scope_digest) !== item.scope_digest)
      || (item.assignment_id && report.scope?.focus_assignment_id !== item.assignment_id)
      || typeof report.agent_session_id !== "string" || !report.agent_session_id) throw new Error("视角报告与工作包身份不匹配。");
    sessions.add(report.agent_session_id);
    for (const finding of report.findings ?? []) {
      if (typeof finding.finding_id !== "string" || !finding.finding_id) throw new Error("报告 finding_id 无效。");
      findings.add(finding.finding_id);
    }
  }
  if (sessions.size !== 1) throw new Error("同一工作包项的三个视角必须由同一次专业会话完成。");
  return { bindings: reports.map(({ lens, path, sha256 }) => ({ lens, path: path.split(sep).join("/"), sha256 })), findingIds: [...findings].sort() };
}
