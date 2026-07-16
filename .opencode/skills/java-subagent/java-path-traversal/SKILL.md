---
name: java-path-traversal
description: "Detect Java path traversal / Zip Slip / unsafe file path use when attacker-controlled path segments reach file read/write/delete/extract without normalize + base-dir confinement. Use for CWE-22 audits, ZipEntry.getName extract loops, multipart getOriginalFilename, download-by-filename, Paths.get/resolve, and File I/O. Keywords: path traversal, Zip Slip, CWE-22, directory traversal, ../, ZipEntry, getOriginalFilename, Path.normalize, startsWith baseDir, FileInputStream."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D5
  weakness: path-traversal
  source: vuln_skill_builder
---

# Java Path Traversal Detection Skill

## Goal

识别攻击者可控路径片段流向文件读/写/删/解压操作，且缺乏有效 normalize + 基目录约束（或等价白名单）的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 JDK File/NIO、Zip/Jar 解压、Servlet multipart、Spring Resource、自定义文件工具类，加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`，不是漏洞。
3. **L2 数据流分析**：从 sink 反向扩展调用链；执行 source-to-sink 可达分析（含 ZipEntry.getName、getOriginalFilename）。
4. **L3 防护分析**：识别 Path.normalize、startsWith(baseDir)、绝对路径拒绝、文件名 allowlist；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API 入口、参数可控性、非测试/死代码、权限与 feature flag。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 payload）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与危险文件 API 关键词
2. **Semgrep**：局部危险模式（`../` 拼接、ZipEntry 解压、getOriginalFilename 直写）
3. **Joern**：跨方法调用链与数据流
4. **CodeQL**：可构建项目的补充分析
5. **LLM**：业务语义、normalize 有效性、基目录边界、符号链接研判

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

- 未发现相关文件路径 sink
- sink 路径完全由常量/固定映射产生且用户输入不进入路径段
- 所有可达路径均经有效 normalize + startsWith(baseDir) 或严格文件名白名单
- 无法建立外部输入到危险文件操作的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- 危险文件 API 命中 ≠ 漏洞
- `FilenameUtils.getName` 单独使用仅为 PARTIAL 控制，不得直接视为 strong sanitizer
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、流向哪、中间经过什么、防护为何无效、攻击者控制了什么路径分量、如何证明可逃出基目录

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D5** / weakness `path-traversal`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-path-traversal-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-path-traversal-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-path-traversal-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`, `java-deserialization-review`) for cross-cutting coverage.
