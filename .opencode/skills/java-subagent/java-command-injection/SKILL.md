---
name: java-command-injection
description: "Detect Java OS command injection by locating attacker-controlled input reaching Runtime.exec/ProcessBuilder/Commons Exec without effective argument separation or allowlisting. Use for Java CMDI audits, CWE-78 review, Runtime.exec concat, ProcessBuilder shell wrappers, and OS command construction analysis. Keywords: command injection, CMDi, CWE-78, Runtime.exec, ProcessBuilder, /bin/sh -c, Apache Commons Exec, OS command, shell metacharacter."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D1
  weakness: command-injection
  source: vuln_skill_builder
---


# Java OS Command Injection Detection Skill

## Goal

识别攻击者可控输入流向 OS 命令构造/执行点，且缺乏有效参数列表分离或命令/参数白名单的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 Runtime / ProcessBuilder / Apache Commons Exec / 自定义 shell 封装，加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`，不是漏洞。
3. **L2 数据流分析**：从 sink 反向扩展调用链；执行 source-to-sink 可达分析。
4. **L3 防护分析**：识别参数列表模式、固定命令映射、参数白名单、Java API 替代；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API 入口、参数可控性、非测试/死代码、权限与 feature flag。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 payload）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与危险 API 关键词
2. **Semgrep**：局部危险模式（字符串拼接命令、`/bin/sh -c`、Runtime.exec concat）
3. **Joern**：跨方法调用链与数据流
4. **CodeQL**：可构建项目的补充分析
5. **LLM**：业务语义、shell vs 参数列表、防护有效性研判

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

- 未发现相关命令执行 sink
- sink 命令完全由常量/固定映射产生且用户输入仅作独立参数（无 shell 解释）
- 所有可达路径均经有效命令白名单或纯 Java API 替代
- 无法建立外部输入到危险命令构造的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- 危险 API 命中 ≠ 漏洞
- `ProcessBuilder` 参数列表模式（无 shell）且输入仅为单一 argv 时，需单独评估，不得直接报 Finding
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、流向哪、中间经过什么、防护为何无效、攻击者控制了什么、如何证明可达

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D1** / weakness `command-injection`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-command-injection-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-command-injection-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-command-injection-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`) for cross-cutting coverage.
