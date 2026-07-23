---
name: java-jwt-misuse
description: "Detect Java JWT/JOSE misuse by locating alg=none acceptance, missing signature verification, weak/hardcoded HMAC secrets, algorithm confusion (RS→HS), and missing exp/aud/iss claim validation (CWE-347/CWE-345). Use for JWT audits, jjwt/nimbus-jose-jwt/auth0 java-jwt/Spring OAuth2 Resource Server review, parseClaimsJws without verify, JWT parser allow none, HS256 secret hardcoded, RSA public key as HMAC secret, and unvalidated claims. Keywords: JWT, JOSE, JWS, alg=none, CWE-347, CWE-345, jjwt, nimbus-jose-jwt, auth0 java-jwt, Spring Security OAuth2 Resource Server, algorithm confusion, hardcoded secret, missing exp, audience validation, signature bypass."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D2
  weakness: jwt-misuse
  source: vuln_skill_builder
---

# Java JWT/JOSE Misuse Detection Skill

## Goal

识别 JWT/JWS 解析与校验中的误用：接受 `alg=none`、未校验签名、弱/硬编码 HMAC 密钥、算法混淆（RSA 公钥当 HMAC 密钥）、以及缺失 `exp`/`aud`/`iss` 等关键声明校验，使身份/完整性/授权保证无法成立的可达路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- 安全配置路径（可选：`application*.yml`、`SecurityFilterChain`、JWT decoder bean）
- 已知认证入口范围（可选）

## Workflow

1. **L0 技术栈识别**：识别 jjwt、nimbus-jose-jwt、auth0 java-jwt、Spring OAuth2 Resource Server / JwtDecoder；加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `JwtCandidate`（parse/verify/decoder 调用、密钥构造、claims 访问），不是漏洞。
3. **L2 配置与数据流**：追踪 token 来源（Header/Cookie/参数）、密钥/算法配置、parse 是否绑定 verify、claims 是否校验。
4. **L3 防护/安全模式分析**：对照 strong 模式（强制算法白名单、密钥管理、`requireExp`/`requireAudience`/`requireIssuer`、Jwks 验签）；分级评估 sanitizer。
5. **L4 可达性与影响面**：确认生产鉴权路径、非测试/示例、token 是否用于授权决策。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：多数为静态语义即可；仅在授权环境按 `validation/playbook.yaml` 做**抽象**验证（禁止对生产系统伪造真实 token 攻击）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：JWT 库 import、parse/verify/decoder、密钥常量、`none`/`HS256`/`requireExp`
2. **Semgrep/OpenGrep**：通过 `semgrep_scan` 执行本地兼容规则，定位 alg=none、parse 无 verify、硬编码 secret、算法混淆模式、claims 未校验
3. **Joern**：跨方法 token→parse→claims 使用链与密钥传播
4. **LLM**：业务语义（是否鉴权决策）、算法白名单有效性、Spring decoder 配置研判

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

## Detection Model Adaptation

本 Skill 以 **pattern-detection + 配置语义** 为主，辅以 token→claims 数据流：

- **sources**：外部 JWT 字符串、密钥/算法配置、Jwks URL、issuer/audience 配置
- **sinks**：JWT parse/verify/decode、claims 读取用于授权、`setSigningKey`/`withSecret`/`NimbusJwtDecoder`
- **sanitizers**：强制算法白名单、非对称验签、密钥管理、`exp`/`nbf`/`aud`/`iss` 强制校验

危险 API 命中 ≠ 漏洞；须确认：误用模式 + 用于鉴权/信任决策 + 可达 + 无有效替代控制。

## Stop Conditions

- 未发现 JWT parse/decode/verify 相关 sink
- 所有路径强制验签 + 算法白名单 + 密钥非硬编码 + exp/aud/iss 完备
- 仅测试/示例 JWT 工具且生产不可达
- 无法建立 token 输入到信任决策的可信路径
- 证据不足以满足 Evidence Contract

## Output Rules

- JWT 库 API 命中 ≠ Finding
- 静态语义清晰（如 `parse` 无 verify、`alg=none` 允许、secret `"secret"`、无 `requireExp`）可升 Finding
- 无完整证据时输出 **Candidate**
- **禁止**输出可用于生产攻击的真实 token 伪造步骤；仅抽象 PoC 与假密钥
- 每个 Finding 必须回答：token 从哪来、如何解析/验签、密钥/算法从哪来、claims 是否校验、攻击者控制了什么、如何证明可达

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D2** / weakness `jwt-misuse`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-jwt-misuse-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-jwt-misuse-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-jwt-misuse-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`, `java-deserialization-review`) for cross-cutting coverage.
