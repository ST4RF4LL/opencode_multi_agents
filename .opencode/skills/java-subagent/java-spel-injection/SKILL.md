---
name: java-spel-injection
description: "Detect Java SpEL / Spring Expression Language injection by locating attacker-controlled strings reaching SpelExpressionParser.parseExpression, Expression.getValue/setValue, or dynamic @Value/#{...} evaluation without SimpleEvaluationContext or allowlisting. Use for Java SpEL audits, CWE-917/CWE-94 review, StandardEvaluationContext abuse, template ParserContext, and Spring EL sink analysis. Keywords: SpEL injection, Spring Expression Language, CWE-917, CWE-94, SpelExpressionParser, parseExpression, Expression.getValue, StandardEvaluationContext, SimpleEvaluationContext, @Value, TemplateParserContext."
license: MIT
compatibility: opencode
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D1
  weakness: spel-injection
  source: vuln_skill_builder
---

# Java SpEL / Expression Language Injection Detection Skill

## Goal

识别攻击者可控字符串流向 SpEL 解析/求值点，且缺乏 SimpleEvaluationContext、表达式白名单或等价限制的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 spring-expression / SpelExpressionParser / EvaluationContext / @Value / Spring Integration SpEL，加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`，不是漏洞。重点：`parseExpression`、`getValue`/`setValue`、动态 `@Value("#{...}")`、`StandardEvaluationContext` 危险 root。
3. **L2 数据流分析**：从 sink 反向扩展调用链；执行 source-to-sink 可达分析（表达式字符串、模板片段、上下文 root/variables）。
4. **L3 防护分析**：识别 SimpleEvaluationContext、类型/方法定位限制、表达式白名单、仅编译期常量表达式；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API 入口、参数可控性、非测试/死代码、权限与 feature flag。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 payload；禁止武器化 RCE 载荷库）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与危险 API 关键词
2. **Semgrep**：局部危险模式（parseExpression 拼接、user string getValue、StandardEvaluationContext）
3. **Joern**：跨方法调用链与数据流；SimpleEvaluationContext 作为控制信号
4. **CodeQL**：可构建项目的补充分析
5. **LLM**：业务语义、EvaluationContext 能力面、防护有效性研判

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

- 未发现相关 SpEL / Spring EL sink
- 表达式完全由编译期常量产生，且用户输入不进入表达式字符串或危险 root
- 所有可达路径均经 SimpleEvaluationContext（受限）或严格表达式白名单
- 无法建立外部输入到危险解析/求值的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- 危险 API 命中 ≠ 漏洞
- 使用 `SimpleEvaluationContext` 且无自定义危险 property/method accessor 时，需单独评估，不得直接报 Finding
- 常量 `@Value("#{systemProperties['x']}")` 类编译期表达式 ≠ 用户可控 SpEL 注入
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、流向哪、中间经过什么、防护为何无效、攻击者控制了什么、如何证明可达

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D1** / weakness `spel-injection`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-spel-injection-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-spel-injection-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-spel-injection-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`, `java-deserialization-review`) for cross-cutting coverage.
