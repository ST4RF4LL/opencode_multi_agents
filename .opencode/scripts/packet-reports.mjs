import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { FINDING_DETAIL_CONTRACT, validateFindingReportDetails } from "../skills/common-subagent/finding-evidence-contract/scripts/finding-report-details.mjs";
import { validateBacAttachment } from "../lib/bac/contract.mjs";

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
  if (item.finding_detail_contract != null && item.finding_detail_contract !== FINDING_DETAIL_CONTRACT) throw new Error("工作包漏洞交付内容契约版本不受支持。");
  if (!Array.isArray(reports) || reports.length !== 3 || new Set(reports.map(entry => entry.lens)).size !== 3
    || reports.some(entry => !PACKET_LENSES.includes(entry.lens))) throw new Error("工作包必须绑定三个不同视角的报告。");
  const root = resolve(reportsRoot), realRoot = await realpath(root);
  const seenPaths = new Set(), sessions = new Set(), findings = new Set();
  let bacAnalysis = null;
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
    if (!Array.isArray(report.findings ?? [])) throw new Error("视角报告 findings 必须是数组。");
    if (!item.bac_analysis && (report.bac_analysis || (report.findings ?? []).some(finding => finding.bac_source))) throw new Error("未启用越权专项的工作包不得接入专项制品。");
    if (item.bac_analysis && binding.lens === "control-driven") {
      bacAnalysis = await validateBacAttachment({ reportsRoot, attachment: report.bac_analysis, item, auditId, findings: report.findings ?? [], sessionId: report.agent_session_id });
    }
    if (binding.lens !== "control-driven" && (report.findings ?? []).some(finding => finding.bac_source)) throw new Error("BAC 差分候选应在 control-driven 报告中交付，其他视角保留独立事实。");
    if (item.finding_detail_contract === FINDING_DETAIL_CONTRACT && !Array.isArray(report.findings)) throw new Error("视角报告必须显式提供 findings 数组，无候选时使用空数组。");
    for (const finding of report.findings ?? []) {
      if (typeof finding.finding_id !== "string" || !finding.finding_id) throw new Error("报告 finding_id 无效。");
      const detailErrors = validateFindingReportDetails(finding, { required: item.finding_detail_contract === FINDING_DETAIL_CONTRACT });
      if (detailErrors.length) throw new Error(`漏洞 ${finding.finding_id} 的交付内容不足：${detailErrors.join("、")}`);
      findings.add(finding.finding_id);
    }
  }
  if (sessions.size !== 1) throw new Error("同一工作包项的三个视角必须由同一次专业会话完成。");
  return { bindings: reports.map(({ lens, path, sha256 }) => ({ lens, path: path.split(sep).join("/"), sha256 })), findingIds: [...findings].sort(),
    ...(bacAnalysis ? { bac_analysis: bacAnalysis } : {}) };
}
