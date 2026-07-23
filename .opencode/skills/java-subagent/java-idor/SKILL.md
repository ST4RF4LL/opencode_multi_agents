---
name: java-idor
description: "Detect Java Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA) by locating object identifiers from requests used to load, update, or delete resources without ownership, tenant, role, or parent-child relationship checks. Use for Java IDOR/BOLA audits, CWE-639/CWE-862/CWE-284 review, Spring MVC path variables and request params as resource keys, Spring Data findById/delete without ownership filter, multi-tenant tenantId from client, horizontal/vertical privilege on object IDs, missing authorization on mutations, and child B CRUD that is not bound to authorization on parent A. Keywords: IDOR, BOLA, CWE-639, CWE-862, CWE-284, A01:2021, object-level authorization, parent-child authorization, nested resource, ownership check, tenant isolation, findById, PathVariable id, horizontal privilege, vertical privilege, mass assignment of tenant."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D3
  weakness: idor
  source: vuln_skill_builder
---

# Java IDOR / BOLA Detection Skill

## Goal

识别攻击者可控的对象标识（path/query/body 中的 id、uuid、orderId、userId、tenantId 等）流向资源加载/更新/删除操作，且缺乏有效对象级授权（ownership / tenant / role 校验）的可达路径。对于语义上依赖父资源 A 的子资源 B，逐项审查 B 的 create/read/update/delete/list/export：必须同时证明调用者获准操作 A，以及 B 与该 A 的归属关系被服务端绑定。认证存在 ≠ 对象级授权存在；嵌套路由存在 ≠ 父子授权绑定存在。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围与认证模型（可选）

## Workflow

1. **L0 技术栈识别**：识别 Servlet / Spring MVC / Spring Data / Spring Security，加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），定位按请求 ID 加载/变更资源的 API，输出 `SinkCandidate`，不是漏洞。
3. **L2 数据流分析**：从 sink 反向扩展调用链；执行 source-to-sink（object id → repository/service access）。
4. **L3 防护分析**：识别 ownership 比较、tenant 过滤、`@PreAuthorize`、SecurityExpression、查询级 `and userId = ?`；对 A → B 审查 `authorize(A)`、`B belongsTo A` 与 CRUD 操作是否在同一服务端信任链内绑定；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API 入口、认证要求、非测试/死代码、角色边界。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（仅 lab/授权环境；禁止复用历史 payload）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与资源访问关键词（findById、deleteById、PathVariable、tenantId）
2. **Semgrep/OpenGrep**：通过 `semgrep_scan` 执行本地兼容规则，定位路径 id 直查、删除无 owner、client tenantId
3. **Joern**：跨方法调用链与数据流
4. **LLM**：业务语义、资源归属模型、水平/垂直越权研判

## Progressive Loading

| 阶段 | 加载内容 |
|------|----------|
| 初始化 | `SKILL.md`, `manifest.yaml`, `scope/definition.yaml` |
| 技术栈识别后 | `models/frameworks/<stack>.yaml`, `models/sources.yaml`, `models/sinks.yaml` |
| 规则执行 | `rules/grep/keywords.yaml`, `rules/semgrep/*`, `rules/joern/*` |
| 命中候选后 | `models/sanitizers.yaml`, `models/propagators.yaml`, `analysis/*` |
| 语义研判 | 相似 `cases/*/lessons.yaml` |
| 验证 | `validation/*` |
| 输出 | `evidence/contract.yaml`, `evidence/finding-schema.yaml` |

## Stop Conditions

- 未发现按外部 ID 访问资源的 sink
- 所有可达路径均经有效 ownership/tenant/role 对象级校验
- 资源为公开只读且无敏感数据边界
- 无法建立外部 object id 到资源操作的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- `findById` / `deleteById` API 命中 ≠ 漏洞
- 认证（logged-in）≠ 对象级授权；必须证明缺少 ownership/tenant/role 约束
- 对 parent A → child B：将每一个 B 操作按 `(principal, A, B, operation)` 证明。`/a/{aId}/b/{bId}`、客户端 `aId`、或仅检查 B 的通用角色均不是关系授权证据；必须验证 B 属于已授权的 A。
- 若 B 的独立对象策略可证明等价于 A 的授权策略，且 B→A 关系不可被该操作绕过或篡改，可 Rejected；无法证明等价性时保留 Candidate。
- 公开目录、全局配置等无归属资源需单独评估，不得直接报 Finding
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：object id 从哪来、访问了什么资源、中间经过什么、为何缺少对象级授权、攻击者可读写谁的对象、如何证明可达

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D3** / weakness `idor`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-idor-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-idor-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-idor-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`, `java-deserialization-review`) for cross-cutting coverage.
