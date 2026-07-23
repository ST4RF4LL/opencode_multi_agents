---
name: java-file-upload
description: "Detect Java unsafe file upload (CWE-434) when attacker-controlled files are accepted without effective type/extension allowlisting, Content-Type-only trust, double-extension bypass, or storage of dangerous types under web-accessible paths. Use for unrestricted upload, executable-in-webroot, MIME-only validation, SVG/HTML stored content, servlet/Spring/Commons multipart. Keywords: file upload, CWE-434, unrestricted upload, getOriginalFilename, Content-Type, double extension, webroot, MultipartFile, transferTo, .jsp acceptance, MIME validation, SVG XSS stored."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D5
  weakness: file-upload
  source: vuln_skill_builder
---

# Java Unsafe File Upload Detection Skill

## Goal

识别攻击者可控上传内容在缺乏有效扩展名/类型 allowlist（或等价策略）的情况下被接受，并可能以危险类型写入可执行/可访问路径（尤其 webroot），或仅信任 Content-Type / 可被双扩展名等绕过的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 Servlet multipart、Spring MultipartFile、Commons FileUpload、自定义 UploadService，加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`（transferTo / Files.copy / 写 webapp 路径），不是漏洞。
3. **L2 数据流分析**：从 sink 反向扩展；追踪 getOriginalFilename、getContentType、Part 字节流到存储路径与策略判断。
4. **L3 防护分析**：识别扩展名 allowlist、服务端 MIME sniff、随机存储名、非 webroot 存储、内容消毒；按 sanitizer 分级。
5. **L4 入口与可达性**：确认上传 API 可达、非测试代码、权限与 feature flag。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：按 `validation/playbook.yaml` 推导目标专用方案；**禁止 webshell 实装**，仅用 FAKE marker / 概念性危险扩展名验收。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：multipart / transferTo / webapp 存储 / Content-Type 校验关键词
2. **Semgrep/OpenGrep**：通过 `semgrep_scan` 执行本地兼容规则，定位无扩展名校验直存、仅 MIME 校验、双扩展名、webroot 路径
3. **Joern**：跨方法调用链与数据流
4. **LLM**：存储位置是否 web-accessible、策略是否可绕过、业务语义研判

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

- 未发现上传存储 sink
- 上传仅落非 web 目录且扩展名/类型 allowlist 有效且 fail-closed
- 所有可达路径均经服务端生成名 + 严格类型策略 + 非执行存储
- 无法建立外部上传到危险存储的可信路径
- 证据不足以满足 Evidence Contract
- 仅 path `../` 逃逸而无类型策略问题 → 转交 **java-path-traversal**

## Output Rules

- multipart / transferTo 命中 ≠ 漏洞
- pure `../` path escape without upload policy issue → **java-path-traversal**，本 Skill 仅作相邻备注
- **禁止** 生成或要求 webshell 实装 payload；验证使用 FAKE markers / empty conceptual `.jsp` 接受证明
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、存到哪、类型策略为何无效、是否可 web 访问/执行、如何证明

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D5** / weakness `file-upload`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-file-upload-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-file-upload-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-file-upload-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`, `java-deserialization-review`) for cross-cutting coverage.
