---
name: java-ssrf
description: "Detect Java Server-Side Request Forgery (SSRF) by locating attacker-controlled network destination data reaching server-side HTTP/URL open operations without effective host/protocol/port allowlisting. Use for Java SSRF audits, CWE-918 review, RestTemplate/WebClient/OkHttp/HttpClient/URLConnection destination control, cloud metadata access, and redirect-bypass analysis. Keywords: SSRF, CWE-918, A10:2021, RestTemplate, WebClient, OkHttp, Apache HttpClient, URL.openConnection, HttpURLConnection, 169.254.169.254, open redirect vs SSRF, host allowlist, protocol smuggling."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D6
  weakness: ssrf
  source: vuln_skill_builder
---

# Java SSRF Detection Skill

## Goal

识别攻击者可控的网络目标信息（完整 URL / host / port / scheme / 可逃逸 path 拼接）流向服务端网络访问操作，且缺乏有效目标约束（host/protocol/port allowlist、解析后校验、重定向再校验）的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- OpenAPI / 路由信息（可选）
- 已知入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 Servlet / Spring RestTemplate / WebClient / Apache HttpClient / OkHttp / JDK URLConnection，加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SinkCandidate`，不是漏洞。
3. **L2 数据流分析**：从 sink 反向扩展调用链；执行 source-to-sink 可达分析。
4. **L3 防护分析**：识别固定目标映射、host allowlist、scheme 限制、DNS/IP 校验、redirect 控制；按 sanitizer 分级评估。
5. **L4 入口与可达性**：确认 API 入口、参数可控性、非测试/死代码、权限与 feature flag。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：证据不足时按 `validation/playbook.yaml` 推导目标专用验证方案（禁止复用历史 payload）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：技术栈与危险 API 关键词
2. **Semgrep/OpenGrep**：通过 `semgrep_scan` 执行本地兼容规则，定位用户 URL 直接传入客户端、host 拼接、弱前缀校验
3. **Joern**：跨方法调用链与数据流
4. **LLM**：业务语义、目标控制面（URL/host/port/path）、防护有效性研判

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

- 未发现相关网络请求 sink
- sink 目标完全由常量/固定映射产生且用户输入不进入 destination 组件
- 所有可达路径均经有效解析后 host/scheme/IP allowlist，且重定向再校验完备
- 无法建立外部输入到网络目标的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- 危险 HTTP 客户端 API 命中 ≠ 漏洞
- 仅 path 可控且 host/scheme 固定时，需单独评估（通常非完整 SSRF），不得直接报 Finding
- open redirect（仅浏览器跳转、无服务端 fetch）不在本 Skill 范围
- 无完整证据时输出 **Candidate**，不得直接报告 Finding
- 每个 Finding 必须回答：输入从哪来、流向哪、中间经过什么、防护为何无效、攻击者控制了什么 destination 组件、如何证明可达

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D6** / weakness `ssrf`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-ssrf-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-ssrf-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-ssrf-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`, `java-deserialization-review`) for cross-cutting coverage.
