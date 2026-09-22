import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { buildLocalAuditSummary } from "../../scripts/build-local-audit-summary.mjs";
import { readAuditTodo } from "../../scripts/audit-todo-core.mjs";
import { BAC_CONTRACT, objectDigest, requireBac } from "./contract.mjs";
import { renderFinalReport, validateFinalReportModel } from "../../skills/common-subagent/audit-coverage-accounting/scripts/final-report-model-core.mjs";

export async function verifyBacFinalReport({ audit, reportsRoot }) {
  if (audit.bac_analysis?.mode !== "auto") return true;
  const todo = await readAuditTodo(audit.todo_path);
  const plan = JSON.parse(await readFile(todo.plan_path, "utf8"));
  requireBac(plan.bac_analysis?.contract_version === BAC_CONTRACT && plan.bac_analysis.mode === "auto", "最终 Plan 遗漏创建任务时启用的越权专项。");
  const summary = await buildLocalAuditSummary({ auditId: audit.id, planPath: todo.plan_path, todoPath: audit.todo_path, reportsRoot });
  const model = JSON.parse(await readFile(join(reportsRoot, "final", `security-audit-report-model.${audit.id}.json`), "utf8"));
  requireBac(model.audit_id === audit.id && model.scope_digest === plan.scope_digest && !validateFinalReportModel(model).length, "最终报告模型无效。");
  requireBac(model.bac_analysis && objectDigest(model.bac_analysis) === objectDigest(summary.bac_analysis), "最终报告越权专项与工作包证据不一致。");
  requireBac((summary.bac_analysis.gaps ?? []).every(gap => model.residual_gaps?.includes(`越权专项：${gap}`)), "最终报告遗漏越权专项缺口。");
  const markdown = await readFile(join(reportsRoot, "final", `security-audit-report.${audit.id}.md`), "utf8");
  requireBac(markdown === renderFinalReport(model), "最终中文报告与专项模型不一致。");
  return true;
}
