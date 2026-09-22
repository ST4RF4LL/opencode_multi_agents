import { stageDeliveryRegistryDigest } from "../../skills/common-subagent/audit-artifact-management/scripts/stage-delivery-contract.mjs";
import { bacStageRegistry } from "../bac/stage-registry.mjs";

// Explicit protocol selection leaves legacy registry semantics unchanged.
export function runtimeStageRegistry(registry, protocol = process.env.AUDIT_RUNTIME_PROTOCOL, bacMode = process.env.AUDIT_BAC_MODE) {
  registry = bacStageRegistry(registry, bacMode);
  if (!registry || protocol !== "runtime-testing.v1" || registry.registry_id?.endsWith("runtime-testing-v1") || registry.purpose?.startsWith("runtime-testing.v1：")) return registry;
  function project(value) {
    if (Array.isArray(value)) return value.filter(item => item !== "P08_FINALIZE.quick-dynamic-validator" && item?.agent_name !== "quick-dynamic-validator").map(project);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, project(item)]));
    if (value === "quick-dynamic-result-set") return "runtime-testing-evidence-set";
    if (value === "reports/validation/quick/{audit_id}.r{round}.json") return "reports/runtime-testing/{audit_id}/evidence-set.json";
    if (value === "quick-dynamic-validator-or-controller") return "runtime-testing-controller";
    if (value === "quick_dynamic_task_opt_in") return "runtime_testing_protocol";
    if (value === "quick_confirmed_ids") return "runtime_supported_ids";
    if (value === "statically_reviewed_ids") return "evidence_reviewed_ids";
    return value;
  }
  const output = project(registry);
  for (const contract of output.contracts ?? []) {
    if (["vulnerability-validator", "vulnerability-affirmative", "vulnerability-negative", "vulnerability-moderator"].includes(contract.agent_name)) {
      contract.input.optional_payload_fields.push("runtime_candidate_ids");
      contract.output.optional_payload_fields.push("runtime_candidate_ids");
    }
  }
  const validation = output.stages?.find(stage => stage.stage_id === "validation");
  if (validation) {
    validation.objective = "消费贯穿式运行测试的封存证据，与源码事实一起进行独立正反复核和 Moderator 裁定，再生成 CVSS、攻击链与报告。";
    validation.recovery_policy.resume_rule = "按运行证据、intake、三方复核、routing 绑定检查，从最早缺失项恢复；环境状态不明时保留隔离和静态结论，不重跑 quick。";
    validation.integration_notes = ["缺少有效授权环境时所有动态环节 SKIPPED；动态支持也必须由三方独立复核。", "运行测试与静态审计交错进行，不追加固定时长验证批次。"];
  }
  output.purpose = `runtime-testing.v1：${registry.purpose}`;
  if (output.registry_id) {
    output.registry_id = `workbench-stage-deliveries-runtime-testing-v1${output.bac_analysis ? "-bac-v1" : ""}`;
    output.registry_digest = stageDeliveryRegistryDigest(output);
  }
  return output;
}
