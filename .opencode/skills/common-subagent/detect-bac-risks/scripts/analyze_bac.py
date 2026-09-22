#!/usr/bin/env python3
"""Evidence-aware deterministic ACP/path comparison; never contacts a target.

Adapted from bacagent_reproduction detect-bac-risks (see ../references/provenance.json).
The original D/O/R/AC model and legacy exact-role join remain supported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

TUPLE_KEYS = {"D", "O", "R", "AC"}
OPERATIONS = {"CREATE", "READ", "UPDATE", "DELETE"}
ACP_CONTROLS = {"NONE", "VAC", "HAC", "VAC+HAC"}
CONTROL_FIELDS = {
    "VAC": ("observed", "trusted_identity", "role_match", "dominates_sink", "fail_closed"),
    "HAC": ("observed", "trusted_principal", "owner_relation_enforced", "dominates_sink", "fail_closed"),
}


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def rows(value: Any, key: str) -> list:
    require(isinstance(value, dict) and isinstance(value.get(key), list), f"{key} 必须是数组。")
    return value[key]


def unique(items: list) -> list:
    found = {}
    for item in items:
        found[json.dumps(item, ensure_ascii=False, sort_keys=True)] = item
    return [found[key] for key in sorted(found)]


def tuple_key(value: Any) -> tuple:
    require(isinstance(value, dict) and set(value) == TUPLE_KEYS, "策略必须恰好包含 D/O/R/AC。")
    require(all(text(value[k]) for k in TUPLE_KEYS), "四元组值必须是非空字符串。")
    require(value["O"] in OPERATIONS and value["AC"] in ACP_CONTROLS, "四元组操作或控制类型无效。")
    require(value["R"].upper() != "UNKNOWN", "未解析角色不得形成最终 ACP。")
    return value["D"], value["O"], value["R"]


def evidence(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, dict) for item in value)


def check_evidence_shapes(value: Any) -> None:
    if isinstance(value, list):
        for item in value:
            check_evidence_shapes(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if key in ("evidence", "policy_binding_evidence"):
                require(isinstance(item, list) and all(isinstance(ref, dict) for ref in item),
                        f"{key} 必须是结构化证据数组。")
            check_evidence_shapes(item)


def evaluate_control(path: dict, control: str) -> dict:
    value = path.get("implemented_controls", {}).get(control.lower(), {})
    require(isinstance(value, dict), f"{control} 控制事实必须是对象。")
    fields = CONTROL_FIELDS[control]
    for field in fields:
        require(value.get(field) is None or type(value[field]) is bool, f"{control}.{field} 必须是布尔值或 null。")
    known = [field for field in fields if value.get(field) is not None]
    refs = value.get("evidence", [])
    proven = evidence(refs)
    # A bare boolean is not evidence of an effective or absent guard.
    missing = [field for field in fields if value.get(field) is False] if proven else []
    unknown = [field for field in fields if value.get(field) is None or not proven]
    state = "MISSING" if missing else "UNKNOWN" if unknown else "EFFECTIVE"
    reasons = [f"{field}=false" for field in missing]
    if unknown:
        reasons.append("待补证事实：" + ", ".join(unknown))
    if known and not proven:
        reasons.append("控制断言没有可复核证据。")
    return {"control": control, "state": state, "reasons": reasons, "evidence": refs,
            "unknown_fields": unknown}


def confidence_for(policy: dict, path: dict, gaps: list) -> tuple:
    score = float(policy["confidence"])
    if gaps:
        score = min(0.64, max(0.0, score - 0.1 * len(gaps)))
    score = round(score, 2)
    return score, "HIGH" if score >= .85 else "MEDIUM" if score >= .65 else "LOW"


def analyze(acp_data: dict, path_data: dict, api_data: dict | None = None,
            input_paths: dict | None = None) -> dict:
    check_evidence_shapes([acp_data, path_data, api_data])
    policies = {}
    gaps = []
    for item in rows(acp_data, "quadruples"):
        require(isinstance(item, dict), "ACP 条目必须是对象。")
        key = tuple_key(item.get("tuple"))
        require(key not in policies, f"重复 ACP：{key}")
        confidence = item.get("confidence")
        require(type(confidence) in (float, int) and math.isfinite(confidence) and 0 <= confidence <= 1,
                "ACP confidence 必须是 0–1 的有限数值。")
        policies[key] = item
    paths = rows(path_data, "paths")
    repositories = [item.get("repository", {}) for item in (acp_data, path_data, api_data) if item is not None]
    binding_verified = all(isinstance(repo, dict) and text(repo.get("scope_digest")) for repo in repositories)
    if binding_verified:
        binding_verified = len({(repo.get("root"), repo.get("scope_digest")) for repo in repositories}) == 1
    revisions = {repo.get("revision") for repo in repositories if isinstance(repo, dict) and repo.get("revision") not in (None, "unknown", "")}
    roots = {repo.get("root") for repo in repositories if isinstance(repo, dict) and text(repo.get("root"))}
    if len(revisions) > 1 or len(roots) > 1 or not binding_verified:
        gaps.append({"code": "SOURCE_BINDING_UNVERIFIED", "reason": "输入仓库、内容快照或版本绑定不完整/不一致。"})
    for label, data in (("acp", acp_data), ("paths", path_data), ("apis", api_data)):
        if data is None:
            gaps.append({"code": "API_CATALOG_MISSING", "reason": "缺少 API 清单，无法判断入口覆盖。"})
            continue
        for key in ("limitations", "known_gaps", "unresolved"):
            require(isinstance(data.get(key, []), list), f"{label}.{key} 必须是数组。")
            for item in data.get(key, []):
                gaps.append({"code": "INPUT_GAP", "input": label, "detail": item})
        coverage = data.get("coverage", {})
        require(isinstance(coverage, dict), f"{label}.coverage 必须是对象。")
        require(isinstance(coverage.get("known_gaps", []), list), f"{label}.coverage.known_gaps 必须是数组。")
        for item in coverage.get("known_gaps", []):
            gaps.append({"code": "INPUT_COVERAGE_GAP", "input": label, "detail": item})
        if coverage.get("status") != "COMPLETE":
            gaps.append({"code": "INPUT_COVERAGE_PARTIAL", "input": label, "reason": "输入全集尚未闭合。"})
        elif not evidence(coverage.get("evidence")):
            gaps.append({"code": "INPUT_COVERAGE_UNPROVEN", "input": label, "reason": "输入完整性声明缺少审查依据。"})
    baseline_gaps = list(gaps)
    findings, results, inconclusive, unmatched, suppressed = [], [], [], [], []
    seen, used, covered = set(), set(), set()
    for path in paths:
        require(isinstance(path, dict) and text(path.get("path_id")), "路径缺少 path_id。")
        pid = path["path_id"]
        require(pid not in seen, f"重复路径：{pid}")
        seen.add(pid)
        sink = path.get("sink", {})
        require(isinstance(sink, dict) and text(sink.get("D")) and sink.get("O") in OPERATIONS, f"{pid} 数据库 sink 无效。")
        require(isinstance(path.get("entrypoint"), dict), f"{pid} 缺少入口。")
        require(path["entrypoint"].get("interface_type", "OTHER") in ("EXTERNAL", "INTERNAL", "OTHER"), "接口类型无效。")
        require(path.get("coverage", "UNKNOWN") in ("COMPLETE", "PARTIAL", "UNKNOWN"), "路径覆盖状态无效。")
        require(isinstance(path.get("implemented_controls", {}), dict), "控制集合必须是对象。")
        require(isinstance(path.get("reachability", {}), dict), "可达性必须是对象。")
        reach = path.get("reachability", {})
        require(reach.get("status", "UNKNOWN") in ("REACHABLE", "UNREACHABLE", "UNKNOWN"), "可达性状态无效。")
        input_flow = path.get("input_flow", {})
        require(isinstance(input_flow, dict), "输入流必须是对象。")
        require(isinstance(path.get("known_gaps", []), list), "路径 known_gaps 必须是数组。")
        require(input_flow.get("attacker_controllable") is None or type(input_flow["attacker_controllable"]) is bool, "可控性必须是布尔值或 null。")
        local = [{"code": "PATH_GAP", "path_id": pid, "detail": item} for item in path.get("known_gaps", [])]
        if path.get("coverage") != "COMPLETE":
            local.append({"code": "PATH_PARTIAL", "path_id": pid})
        if reach.get("status", "UNKNOWN") == "UNKNOWN" or not evidence(reach.get("evidence")):
            local.append({"code": "REACHABILITY_UNPROVEN", "path_id": pid})
        if input_flow.get("attacker_controllable") is None or not evidence(input_flow.get("evidence")):
            local.append({"code": "INPUT_FLOW_UNPROVEN", "path_id": pid})
        binding = path.get("policy_binding")
        if binding is not None:
            key = tuple_key(binding)
            require(key[:2] == (sink["D"], sink["O"]), "策略绑定与数据库操作不一致。")
            require(isinstance(path.get("caller_context"), dict), "显式策略绑定必须保留独立 caller_context。")
            if not evidence(path.get("policy_binding_evidence")):
                local.append({"code": "POLICY_BINDING_UNPROVEN", "path_id": pid})
        else:
            require(text(path.get("effective_role")), "兼容路径缺少 effective_role。")
            key = sink["D"], sink["O"], path["effective_role"]
        api_id = path.get("api_id")
        if text(api_id):
            covered.add(api_id)
        else:
            local.append({"code": "PATH_API_UNMAPPED", "path_id": pid})
        policy = policies.get(key)
        if binding is not None and policy is not None:
            require(binding == policy["tuple"], "策略绑定 AC 与被引用策略不一致。")
        row = {"path_id": pid, "api_id": api_id, "gaps": local, "state": "UNMATCHED"}
        if policy is None:
            unmatched.append({"path_id": pid, "api_id": api_id, "sink": sink, "effective_role": path.get("effective_role"),
                              "type": "UNMATCHED_PATH", "reason": "没有精确匹配的预期策略，不猜测角色。"})
            local.append({"code": "UNMATCHED_PATH", "path_id": pid})
        else:
            used.add(key)
            row["tuple_ref"] = policy["tuple"]
            required = [] if policy["tuple"]["AC"] == "NONE" else policy["tuple"]["AC"].split("+")
            evaluations = {control: evaluate_control(path, control) for control in CONTROL_FIELDS}
            missing = [control for control in required if evaluations[control]["state"] == "MISSING"]
            unknown = [control for control in required if evaluations[control]["state"] == "UNKNOWN"]
            for control in required:
                if evaluations[control]["unknown_fields"]:
                    local.append({"code": "CONTROL_FACTS_UNKNOWN", "path_id": pid, "control": control})
            policy_proven = evidence(policy.get("evidence")) and not any(g["code"] == "POLICY_BINDING_UNPROVEN" for g in local)
            if not policy_proven:
                local.append({"code": "POLICY_UNPROVEN", "path_id": pid})
            if reach.get("status") == "UNREACHABLE" and evidence(reach.get("evidence")):
                row["state"] = "SUPPRESSED_UNREACHABLE"
                suppressed.append({"path_id": pid, "type": "PROVEN_UNREACHABLE", "reachability": reach, "tuple_ref": policy["tuple"]})
            elif missing and policy_proven:
                seed = json.dumps([policy["tuple"], pid, sorted(missing)], sort_keys=True, ensure_ascii=False)
                fid = "BAC-" + hashlib.sha256(seed.encode()).hexdigest()[:16].upper()
                score, band = confidence_for(policy, path, baseline_gaps + local)
                finding = {"finding_id": fid, "status": "CANDIDATE", "classification": "BVAC_BHAC_CANDIDATE" if len(missing) == 2 else "BVAC_CANDIDATE" if missing == ["VAC"] else "BHAC_CANDIDATE",
                           "tuple_ref": policy["tuple"], "path_id": pid, "api_id": api_id, "entrypoint": path["entrypoint"],
                           "interface_type": path["entrypoint"].get("interface_type", "OTHER"), "sink": sink,
                           "caller_context": path.get("caller_context"), "required_controls": required,
                           "effective_controls": [c for c, value in evaluations.items() if value["state"] == "EFFECTIVE"],
                           "missing_controls": missing, "unknown_controls": unknown, "control_evaluation": evaluations,
                           "reachability": reach, "input_flow": input_flow, "attacker_controllable": input_flow.get("attacker_controllable"),
                           "evidence": unique(path.get("evidence", []) + policy.get("evidence", []) + [e for c in required for e in evaluations[c]["evidence"]]),
                           "root_cause": "预期策略要求的控制在此路径上缺失或无效：" + ", ".join(missing),
                           "confidence": score, "confidence_band": band, "review_required": True,
                           "validation_status": "NOT_PERFORMED"}
                findings.append(finding)
                row.update(state="CANDIDATE", finding_id=fid)
            elif unknown or local or not policy_proven:
                row["state"] = "INCONCLUSIVE"
                inconclusive.append({"path_id": pid, "unknown_controls": unknown, "tuple_ref": policy["tuple"], "reason": "路径或策略证据不完整。"})
            else:
                row["state"] = "NO_MISMATCH"
        results.append(row)
        gaps.extend(local)
    unreferenced = [{"tuple_ref": policies[key]["tuple"]} for key in sorted(policies.keys() - used)]
    uncovered, unknown_apis = [], []
    api_ids = set()
    if api_data is not None:
        for api in rows(api_data, "apis"):
            require(isinstance(api, dict) and text(api.get("api_id")) and api["api_id"] not in api_ids, "API 标识无效或重复。")
            api_ids.add(api["api_id"])
            require(api.get("database_relevant") is None or type(api["database_relevant"]) is bool, "API 数据库相关性必须是布尔值或 null。")
            if api.get("database_relevant") is None:
                unknown_apis.append(api)
            elif api["database_relevant"] and api["api_id"] not in covered:
                uncovered.append(api)
        for api_id in sorted(covered - api_ids):
            gaps.append({"code": "PATH_API_NOT_IN_CATALOG", "api_id": api_id})
    out_of_model = acp_data.get("out_of_model", [])
    require(isinstance(out_of_model, list), "out_of_model 必须是数组。")
    complete = not any([gaps, unreferenced, uncovered, unknown_apis, unmatched, inconclusive])
    summary = {"acp_quadruples": len(policies), "access_paths": len(paths), "matched_paths": len(paths) - len(unmatched),
               "findings": len(findings), "inconclusive_paths": len(inconclusive), "unmatched_paths": len(unmatched),
               "suppressed_unreachable_paths": len(suppressed), "unreferenced_acp": len(unreferenced),
               "uncovered_database_relevant_apis": len(uncovered), "unknown_api_relevance": len(unknown_apis),
               "bvac_candidates": sum("VAC" in f["missing_controls"] for f in findings),
               "bhac_candidates": sum("HAC" in f["missing_controls"] for f in findings),
               "analysis_complete": complete, "dynamic_validation_performed": False,
               "out_of_model": len(out_of_model), "no_mismatch_paths": sum(r["state"] == "NO_MISMATCH" for r in results)}
    return {"schema_version": "bac-comparison.v1", "analysis_kind": "STATIC_BAC_CANDIDATE_ANALYSIS",
            "repository": path_data.get("repository", {}), "inputs": input_paths or {}, "summary": summary,
            "findings": sorted(findings, key=lambda r: r["finding_id"]), "path_results": sorted(results, key=lambda r: r["path_id"]),
            "inconclusive": sorted(inconclusive, key=lambda row: row["path_id"]), "unmatched_paths": sorted(unmatched, key=lambda row: row["path_id"]), "suppressed_paths": sorted(suppressed, key=lambda row: row["path_id"]),
            "coverage_gaps": {"unreferenced_acp": unreferenced, "uncovered_apis": sorted(uncovered, key=lambda row: row["api_id"]), "unknown_api_relevance": sorted(unknown_apis, key=lambda row: row["api_id"])},
            "out_of_model": out_of_model, "limitations": unique(gaps), "validation_status": "NOT_PERFORMED"}


def render_markdown(result: dict) -> str:
    def safe(value):
        return str(value).replace("|", "\\|").replace("\n", " ")
    lines = ["# 越权专项静态差分", "", "此结果为待复核候选，未执行动态验证。", "",
             f"策略：{result['summary']['acp_quadruples']}；路径：{result['summary']['access_paths']}；候选：{len(result['findings'])}。",
             f"专项分析完整：{'是（仅限声明范围）' if result['summary']['analysis_complete'] else '否，存在缺口'}。", "",
             "| 路径 | 状态 | 缺口数 |", "|---|---|---:|"]
    lines.extend(f"| {safe(row['path_id'])} | {row['state']} | {len(row['gaps'])} |" for row in result["path_results"])
    for finding in result["findings"]:
        lines.extend(["", f"## {finding['finding_id']}", "", finding["root_cause"], "",
                      f"路径：`{safe(finding['path_id'])}`；静态置信度：{finding['confidence']}；仍须源码复查与独立裁定。"])
    lines.extend(["", "## 覆盖缺口", ""])
    lines.extend("- " + safe(json.dumps(gap, ensure_ascii=False, sort_keys=True)) for gap in result["limitations"])
    for key, values in result["coverage_gaps"].items():
        if values:
            lines.append(f"- {key}：{len(values)} 项。")
    if result["out_of_model"]:
        lines.append(f"- 模型外控制：{len(result['out_of_model'])} 项，继续现有授权审计。")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="静态比较 ACP 与访问路径；不执行目标请求。")
    parser.add_argument("--acp", required=True)
    parser.add_argument("--paths", required=True)
    parser.add_argument("--api-catalog")
    parser.add_argument("--output")
    parser.add_argument("--markdown")
    args = parser.parse_args()
    def read(path):
        return json.loads(Path(path).read_text(encoding="utf-8")) if path else None
    try:
        result = analyze(read(args.acp), read(args.paths), read(args.api_catalog))
        encoded = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(encoded, encoding="utf-8")
        else:
            print(encoded, end="")
        if args.markdown:
            Path(args.markdown).parent.mkdir(parents=True, exist_ok=True)
            Path(args.markdown).write_text(render_markdown(result), encoding="utf-8")
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"越权差分失败：{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
