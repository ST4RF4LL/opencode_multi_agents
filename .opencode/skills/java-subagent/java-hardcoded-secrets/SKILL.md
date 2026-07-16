---
name: java-hardcoded-secrets
description: "Detect hardcoded secrets in Java and config (API keys, passwords, private keys, JWT secrets, DB credentials, cloud access keys) under CWE-798/259/321. Use for secret scanning, credential-in-source audits, application.yml/properties plaintext passwords, SecretKeySpec literals, AKIA* keys, PEM private keys in repo, JWT signing secrets, JDBC URLs with embedded passwords. Boundary: weak algorithms → java-weak-cryptography; this skill = secret material in source/config. Keywords: hardcoded secret, CWE-798, CWE-259, CWE-321, API key, password literal, private key, JWT secret, datasource password, AWS access key, SecretKeySpec, application.yml."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D8
  weakness: hardcoded-secrets
  source: vuln_skill_builder
---

# Java Hardcoded Secrets Detection Skill

## Goal

识别源码、资源与配置中以明文/可逆形式嵌入的密钥材料（API key、密码、私钥、JWT secret、DB 凭证、云访问密钥等），使秘密可被仓库访问者或制品提取者获取，且缺乏有效密钥管理或占位符约束的可达使用路径。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- 配置文件路径（可选：application*.yml/properties、*.xml、*.env 样例）
- 已知密钥管理方式（可选：Vault、KMS、环境变量约定）

## Workflow

1. **L0 技术栈识别**：识别 Spring config、JDBC、AWS SDK、JWT 库、密钥相关 API；加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `SecretCandidate`（字面量、配置键、PEM 块、SecretKeySpec），不是漏洞。
3. **L2 绑定与使用分析**：确认候选是否为真实密钥形态；追踪字面量 → 认证/加密/签名/DB 连接的使用路径。
4. **L3 控制分析**：区分占位符/示例值/测试夹具 vs 生产秘密；识别 env/Vault/KMS 注入；按 sanitizer 分级。
5. **L4 可达性与影响面**：确认非纯测试/文档、是否打入生产制品、密钥类型与权限范围。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：多数为静态语义即可；按 `validation/playbook.yaml` 做有限验证（禁止使用真实密钥、禁止外泄）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：密钥关键词、AKIA*、PEM、password/secret/apiKey 字面量、yml/properties
2. **Semgrep**：硬编码密码/API key/SecretKeySpec/JWT secret/配置明文
3. **Joern**：字面量到认证/加密/DB 调用的绑定与调用链
4. **CodeQL**：可构建项目的补充分析
5. **LLM**：占位符 vs 真实秘密、测试范围、密钥影响面研判

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

本 Skill 以 **secret-material-detection** 为主，非经典注入：

- **sources**：字符串/字节字面量、配置明文、资源文件中的 PEM/密钥
- **sinks**：认证头、DB 连接、`SecretKeySpec`、JWT 签名、云 SDK 凭证、BasicAuth
- **sanitizers**：环境变量/Vault/KMS、明显占位符、测试隔离、密钥轮换与扫描门禁

危险模式命中 ≠ 漏洞；须确认：可识别秘密材料 + 安全敏感用途 + 生产可达/可进制品 + 无有效密钥管理。

## Stop Conditions

- 未发现密钥形态字面量或配置明文
- 全部为明显占位符（CHANGE_ME、your-api-key、***）且未绑定生产路径
- 密钥仅来自 env/Vault/KMS 且源码无明文
- 路径仅测试/示例且不打入生产制品
- 证据不足以满足 Evidence Contract

## Output Rules

- 变量名含 password/secret ≠ Finding
- 静态语义清晰（如 `API_KEY = "AKIA..."`、yml `password: real-looking`、`SecretKeySpec("...".getBytes())`）可升 Finding
- 无完整证据时输出 **Candidate**
- 每个 Finding 必须回答：什么秘密、在哪、如何使用、为何算硬编码、影响面、如何证明可达
- 报告中仅引用已脱敏/明显假密钥；禁止复述疑似真实生产密钥全文

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D8** / weakness `hardcoded-secrets`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-hardcoded-secrets-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-hardcoded-secrets-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-hardcoded-secrets-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`, `java-deserialization-review`) for cross-cutting coverage.
