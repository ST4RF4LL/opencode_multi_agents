---
name: java-weak-cryptography
description: "Detect Java weak cryptography misuse by locating broken algorithms, insecure modes, static IVs, hardcoded keys, insecure random, and weak password hashing (CWE-327/328/330/916). Use for Java crypto audits, JCA/JCE review, Cipher.getInstance analysis, AES/ECB or static-IV GCM, MD5/SHA1 password storage, DES/3DES/RC4, RSA without OAEP, java.util.Random for secrets, and SecureRandom misuse. Keywords: weak crypto, CWE-327, CWE-328, CWE-330, AES/ECB, static IV, MessageDigest MD5, DES, 3DES, RC4, hardcoded key, insecure random, bcrypt, argon2, password hashing, Cipher.getInstance."
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
  dimension: D7
  weakness: weak-cryptography
  source: vuln_skill_builder
---


# Java Weak Cryptography Detection Skill

## Goal

识别弱算法/模式、静态 IV/nonce、硬编码密钥、不安全随机源或弱口令哈希等密码学误用，使机密性/完整性/不可预测性目标无法成立的可达配置与调用。

## Required Inputs

- 项目根目录
- Java 技术栈（可选，可自动识别）
- CPG 路径（可选，Joern）
- 配置文件路径（可选：application*.yml/properties、密钥库引用）
- 已知敏感数据范围（可选：密码、token、PII）

## Workflow

1. **L0 技术栈识别**：识别 JCA/JCE、BouncyCastle、Tink、Spring Security crypto、password encoders；加载对应 framework model。
2. **L1 候选点定位**：执行 sink locator（grep → Semgrep → Joern），输出 `CryptoCandidate`（算法串、Cipher/Digest/Mac/Signature/Random/Key 调用），不是漏洞。
3. **L2 配置与数据流**：追踪算法字符串、密钥/IV/nonce/salt 来源；对 password-hash 与 key-material 建立“敏感数据 → 弱原语”路径。
4. **L3 防护/安全模式分析**：对照 strong algorithms（AES-GCM、SHA-256+、OAEP、SecureRandom、bcrypt/scrypt/argon2）；分级评估 sanitizer。
5. **L4 可达性与影响面**：确认非测试/死代码、密钥是否生产路径、随机用途是否为安全相关（session/token/CSRF/key）。
6. **语义研判**：按 `analysis/decision-tree.yaml` 判定；检索相似 `cases/*/lessons.yaml`。
7. **验证**：多数为静态语义即可；仅在需要时按 `validation/playbook.yaml` 做有限验证（禁止破坏性操作）。
8. **Evidence Contract**：满足 `evidence/contract.yaml` 后输出 Finding；否则 Candidate 或 Rejected。

## Tool Priority

1. **rg**：算法名、Cipher/MessageDigest/SecureRandom/密钥常量
2. **Semgrep**：弱算法字面量、ECB、static IV、Random→secret、硬编码 key
3. **Joern**：跨方法算法/密钥/IV 传播与调用链
4. **CodeQL**：可构建项目的补充分析
5. **LLM**：用途语义（是否安全相关）、algorithm agility、密钥生命周期研判

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

本 Skill 以 **pattern-detection** 为主，非经典 source→sink 注入：

- **sources**：加密配置/算法字符串、密钥材料来源、IV/nonce/salt 来源、口令明文、弱随机种子
- **sinks**：`Cipher.getInstance`、`MessageDigest.getInstance`、`Mac`/`Signature`、`KeyGenerator`、`SecureRandom`/`Random`、password hash API
- **sanitizers**：强算法与正确用法（AES/GCM + 唯一 nonce、SHA-256+、OAEP、`SecureRandom`、bcrypt/scrypt/argon2）

危险 API 命中 ≠ 漏洞；须确认：弱原语 + 安全相关用途 + 可达 + 无有效替代控制。

## Stop Conditions

- 未发现相关 crypto sink / 弱算法模式
- 算法与模式均为 strong，且 IV/nonce 唯一、密钥非硬编码
- 弱原语仅用于非安全用途（如 checksum、cache key）且有明确证据
- 路径仅测试/示例代码且生产不可达
- 证据不足以满足 Evidence Contract

## Output Rules

- 弱算法字面量命中 ≠ Finding
- 静态语义清晰（如 `"AES/ECB/..."`、MD5 存密码、`new Random()` 生成 token）可升 Finding
- 无完整证据时输出 **Candidate**
- 每个 Finding 必须回答：用了什么原语、为何弱、密钥/IV/随机从哪来、影响何种安全属性、如何证明可达

输出结构见 `evidence/finding-schema.yaml`。

## OpenCode Multi-Agent Integration

- Owner agent: `java-source-auditor` (collection `java-subagent`).
- Audit dimension: **D7** / weakness `weak-cryptography`.
- Progressive-load sibling assets in this skill directory (`models/`, `rules/`, `analysis/`, `cases/`, `validation/`, `evidence/`).
- Published Joern rules live under `.opencode/shared/security-audit/joern-rules/java/` with ids `java-weak-cryptography-*`.
- Reusable cases live under `.opencode/shared/security-audit/vulnerability-cases/java/java-weak-cryptography-case-*`.
- False-positive patterns live under `.opencode/shared/security-audit/false-positive-cases/java/java-weak-cryptography-fp.md`.
- Prefer defensive local validation; do not reuse historical payloads as generic exploits.
- Coordinate with thin review skills (`java-injection-review`, `java-web-security-review`) for cross-cutting coverage.
