---
name: java-mass-assignment
description: "Detect Java Mass Assignment / over-posting (CWE-915) where HTTP binding or JSON deserialization maps attacker-controlled fields onto domain entities, allowing privilege, role, balance, ownership, or status overwrite. Use for Spring MVC @ModelAttribute/@RequestBody entity binding, Jackson sensitive-field binding, entity-as-DTO patterns, nested object privilege escalation, PATCH without allowlist, Spring Data REST exposure, and CWE-915 audits. Keywords: mass assignment, over-posting, CWE-915, @ModelAttribute, @RequestBody, isAdmin, role, balance, @JsonIgnore, @JsonProperty(access), DTO, BeanUtils.copyProperties, @InitBinder allowedFields, Spring Data REST, PATCH merge."
license: MIT
compatibility: opencode
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D9
  weakness: mass-assignment
  source: vuln_skill_builder
---

# Java Mass Assignment Detection Skill

## Goal

识别攻击者可控的 HTTP/JSON 字段通过框架绑定、反序列化或属性拷贝写入领域对象的敏感属性（权限/角色/余额/所有权/状态等），且缺乏字段白名单、DTO 隔离或序列化访问控制的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 Spring MVC、Jackson、Spring Data REST；加载对应 framework model。
2. **L1 候选点定位**：执行 binding/sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`（实体绑定入口），不是漏洞。
3. **L2 数据流分析**：从 binding 入口追踪到持久化/授权决策；识别敏感字段是否可被外部赋值。
4. **L3 防护分析**：识别 DTO 隔离、`@JsonIgnore`/`@JsonProperty(access=READ_ONLY)`、`@InitBinder` allowlist、显式 setter 拷贝、PATCH 字段白名单；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API 入口、认证角色、非测试/死代码、绑定目标是否为 JPA/领域实体。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 payload）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与绑定/敏感字段关键词
2. **Semgrep**：局部危险模式（@ModelAttribute 实体、@RequestBody 实体、BeanUtils 全量拷贝）
3. **Joern**：跨方法调用链、实体字段写入、save/update 路径
4. **CodeQL**：可构建项目的补充分析
5. **LLM**：业务语义、敏感字段判定、防护有效性研判

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

- 未发现实体绑定 / JSON 反序列化到领域对象的入口
- 绑定目标仅为无敏感字段的专用 DTO，且无后续 BeanUtils 全量拷贝到实体
- 所有可达路径均经有效字段白名单或序列化只读保护，敏感字段不可写
- 无法建立外部字段到敏感属性赋值的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- 发现 `@RequestBody`/`@ModelAttribute` ≠ 漏洞
- 实体类存在 `isAdmin`/`role` 字段 ≠ 漏洞（需证明可被绑定并产生安全影响）
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、绑定到哪个类型、哪些敏感字段可写、中间如何传播到持久化/授权、防护为何无效、如何证明可达

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D9** / weakness `mass-assignment`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-mass-assignment-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-mass-assignment-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-mass-assignment-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`, `java-deserialization-review`) for cross-cutting coverage.
