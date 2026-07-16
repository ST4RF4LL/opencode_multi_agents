---
name: java-xxe
description: "Detect Java XXE (CWE-611) by locating untrusted XML input reaching XML parsers without secure feature flags (external entities, DTD, XInclude disabled). Use for DocumentBuilderFactory, SAXParserFactory, XMLInputFactory, TransformerFactory, SchemaFactory, JAXB Unmarshaller audits. Keywords: XXE, CWE-611, CWE-827, CWE-776, external entity, disallow-doctype-decl, FEATURE_SECURE_PROCESSING, ACCESS_EXTERNAL_DTD, billion laughs, XInclude, StAX, SAX, DOM."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D1
  weakness: xxe
  source: vuln_skill_builder
---

# Java XXE Detection Skill

## Goal

识别不可信 XML 输入到达 XML 解析器/解组器，且未正确禁用外部实体、DTD、XInclude 或实体展开的可达路径（CWE-611；相关 CWE-827 / CWE-776）。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 DOM/SAX/StAX/Transformer/JAXB/Spring OXM/DOM4J/JDOM，加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`（解析调用 + 工厂配置点），不是漏洞。
3. **L2 数据流分析**：从 parse/unmarshal sink 反向扩展调用链；执行 untrusted XML source-to-sink 可达分析。
4. **L3 防护分析**：识别 `setFeature` / `setProperty` / `setAttribute` 安全配置、`FEATURE_SECURE_PROCESSING`、ACCESS_EXTERNAL_* 空串；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API 入口、参数/上传体可控性、非测试/死代码、权限与 feature flag。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 payload / 禁止武器化 OOB kit）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与危险 API 关键词（DocumentBuilderFactory / XMLInputFactory / TransformerFactory / Unmarshaller）
2. **Semgrep**：局部危险模式（默认工厂 + parse；缺少 secure flags）
3. **Joern**：跨方法调用链、工厂配置与数据流
4. **CodeQL**：可构建项目的补充分析
5. **LLM**：业务语义、配置是否作用于同一工厂实例、DoS vs 文件读取影响分级

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

## Scope Notes

- **Focus**: XXE / insecure XML parser configuration (untrusted XML + missing secure flags).
- **Adjacent / out of scope here**: XPath injection (CWE-643) — owned by `java-xpath-injection`. Generic SSRF is out of scope unless as XXE network-entity *impact*. JSON deserialization is out of scope.
- Do not report XPath injection solely because XML parsers are used; do not dismiss XXE because XPath parameterization is present.

## Stop Conditions

- 未发现相关 XML parse / unmarshal sink
- 所有可达工厂在 parse 前已完整应用 strong secure features
- XML 输入完全来自受信常量/内置资源且无外部可控入口
- 无法建立外部输入到危险解析操作的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- 危险 API 命中 ≠ 漏洞
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、流向哪、中间经过什么、防护为何无效、攻击者控制了什么、如何证明可达
- 区分 **data disclosure / SSRF-via-entity** 与 **entity expansion DoS** 的影响与严重度

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D1** / weakness `xxe`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-xxe-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-xxe-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-xxe-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`, `java-deserialization-review`) for cross-cutting coverage.
