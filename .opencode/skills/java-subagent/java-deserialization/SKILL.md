---
name: java-deserialization
description: "Detect Java unsafe deserialization by locating untrusted data reaching ObjectInputStream/XMLDecoder/Fastjson/Jackson/SnakeYAML/XStream/Hessian/Kryo without type allowlisting or safe constructors. Use for CWE-502 audits, polymorphic typing, autoType, gadget-adjacent sinks. Keywords: deserialization, CWE-502, ObjectInputStream, Fastjson autoType, Jackson enableDefaultTyping, SnakeYAML SafeConstructor, XStream, Hessian, Kryo, XMLDecoder, gadget chain."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D4
  weakness: deserialization
  source: vuln_skill_builder
---

# Java Unsafe Deserialization Detection Skill

## Goal

识别攻击者可控数据流向反序列化 / 多态对象重建 sink，且缺乏有效类型白名单、ObjectInputFilter 或安全构造器的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）
- 依赖清单（pom/gradle，用于 gadget 放大器评估）

## Workflow

1. **L0 技术栈识别**：识别 java-native / fastjson / jackson / snakeyaml / xstream / hessian-kryo / XMLDecoder，加载对应 framework model；扫描 classpath 是否含 gadget 放大器库（commons-collections、commons-beanutils、c3p0 等）——放大器 alone 不是 Finding。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`，不是漏洞。
3. **L2 数据流分析**：从 sink 反向扩展调用链；执行 source-to-sink 可达分析（HTTP body/cookie/header、RPC、MQ/Redis bytes）。
4. **L3 防护分析**：识别 ValidatingObjectInputStream、ObjectInputFilter、SafeConstructor、XStream security framework、Jackson 无 default typing、Fastjson safeMode；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API 入口、参数可控性、非测试/死代码、权限与 feature flag。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`；gadget 库仅作风险放大器。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 gadget payload）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与危险 API / 依赖关键词
2. **Semgrep**：局部危险模式（readObject、JSON.parse + autoType、new Yaml()、enableDefaultTyping）
3. **Joern**：跨方法调用链与数据流
4. **CodeQL**：可构建项目的补充分析
5. **LLM**：业务语义、类型解析策略、防护有效性、与 JNDI 边界判定

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

- 未发现相关反序列化 sink
- sink 输入完全由常量/可信内部存储产生且无外部影响
- 所有可达路径均经有效类型白名单 / ObjectInputFilter / SafeConstructor / 关闭 autoType
- 无法建立外部输入到危险反序列化操作的可信路径
- 证据不足以满足 Evidence Contract
- 纯 Log4Shell JNDI lookup（无 deserial 路径）→ 边界排除，交 java-jndi-injection

## Output Rules

- 危险 API 命中 ≠ 漏洞
- 仅 classpath 存在 gadget 库 ≠ Finding
- Jackson 默认无 typing 的 DTO 反序列化通常安全，不得直接报 Finding
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、流向哪、中间经过什么、类型约束为何无效、攻击者控制了什么、如何证明可达

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D4** / weakness `deserialization`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-deserialization-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-deserialization-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-deserialization-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`, `java-deserialization-review`) for cross-cutting coverage.
