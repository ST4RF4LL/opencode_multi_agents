import { stageDeliveryRegistryDigest } from "../../skills/common-subagent/audit-artifact-management/scripts/stage-delivery-contract.mjs";

export const ACP_STAGE_CONTRACT = "P03_PLAN.security-threat-modeler.acp";
export function bacStageRegistry(registry, mode = process.env.AUDIT_BAC_MODE) {
  if (!registry || mode !== "auto" || registry.bac_analysis === "bac-analysis.v1") return registry;
  const result = structuredClone(registry);
  result.bac_analysis = "bac-analysis.v1";
  if (Array.isArray(result.contracts)) {
    result.contracts.push({ contract_id: ACP_STAGE_CONTRACT, stage_id: "P03_PLAN", agent_name: "security-threat-modeler",
      invocation: "CONDITIONAL", input_scope_state: "FROZEN", output_scope_state: "FROZEN",
      input: { required_artifact_types: ["coverage-plan", "recon-inventory-set"], optional_artifact_types: ["bac-resource-role-catalog"],
        required_payload_fields: ["mode", "scope_digest", "resource_scope", "focus_area_ids"], optional_payload_fields: [] },
      output: { required_artifact_types: ["bac-policy-shard"], optional_artifact_types: ["bac-resource-role-catalog"],
        required_payload_fields: ["scope_digest", "resource_scope", "gaps"], optional_payload_fields: [] } });
    for (const contract of result.contracts) {
      if (["java-source-auditor", "web-source-auditor", "python-source-auditor"].includes(contract.agent_name)) {
        for (const key of ["input", "output"]) contract[key].optional_artifact_types.push("bac-analysis-bundle");
      }
    }
  }
  if (result.registry_id) {
    result.registry_id += "-bac-v1";
    result.registry_digest = stageDeliveryRegistryDigest(result);
  }
  return result;
}
