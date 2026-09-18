# 完整审计证据报告：单项漏洞格式预览

> 本文是合成格式示例，所有文件、会话、摘要与判断均为演示数据，不代表对真实项目进行了审计或动态测试。由当前报告渲染器生成，展示未提供动态环境时的静态证据和验证过程。

### [MEDIUM 6.5] 示例：资源读取缺少对象归属校验

- **Finding ID**：`FIND-EXAMPLE-001`；**最终结论**：真实漏洞。
- **漏洞类型 / 责任域**：EXAMPLE-AUTHZ-01 / web；**Focus Area**：FA-EXAMPLE。
- **主要漏洞位置**：`src/example-resource.js:12`。
- **受影响入口**：资源读取入口；**认证要求**：AUTHENTICATED。
- **身份与边界**：测试账户乙 → 当前登录账户；当前账户的资源边界 → 另一账户的资源边界。

#### 漏洞成因与行为差异

资源读取路径只验证登录状态，未校验资源归属。

- 应有行为：仅允许资源所有者或显式获授权主体读取。
- 实际行为：查询使用外部资源标识，返回前没有主体与归属比较。

#### 代码位置与证据链

**E0 · source · `src/example-resource.js:10`**

请求参数决定待查询资源标识。

取证方法：manual-source；置信度：high；源码摘要：`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`。

**E1 · sink · `src/example-resource.js:12`**

查询后直接返回资源，当前路径未比较主体与资源归属。

取证方法：manual-source；置信度：high；源码摘要：`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`。

代码上下文 · E1 · `src/example-resource.js:12`（上游记录）：

```javascript
const item = repository.find(request.params.id);
return item;
```

**专业审计提供的路径**

1. 已登录请求提供资源标识。（E0）
2. 查询结果未经过归属判断便返回调用者。（E1）

**独立裁决的语义路径**：已证明

1. 独立追踪参数进入查询接口。
2. 独立检查响应前没有对象权限分支。

输入事实：E0；危险操作/配置事实：E1。

框架/版本依据：示例框架 / example-revision；API/配置：repository.find。

- 示例 API 只按资源标识查询，不附加主体过滤。

当前示例路径可返回未按主体筛选的对象。

#### 利用前提、影响与限制

- 两个测试账户拥有各自的独立测试资源。（UNPROVEN；未绑定事实索引）

安全影响：可能读取另一测试账户的资源。

影响范围：SINGLE_USER；证据限于单项资源读取，未证明批量影响。

适用假设：

- 示例入口按记录中的中间件链部署。

审计盲区：

- 没有动态环境，部署层拦截尚未验证。

攻击面独立复核：LIMITED；静态路径已检查，部署假设未验证。

- 已复核入口、主体、资源和响应路径。

攻击面结论限制：

- 不能宣称运行环境已复现。

#### 已检查的防护与反证

| 防护层次 | 状态 | 判断依据 | 证据 |
|---|---|---|---|
| local | ABSENT | 示例检查范围内未找到对象权限防护。 | 示例保护检查记录。 |
| inherited | ABSENT | 示例检查范围内未找到对象权限防护。 | 示例保护检查记录。 |
| global | ABSENT | 示例检查范围内未找到对象权限防护。 | 示例保护检查记录。 |
| deployment | NOT_APPLICABLE | 本例只评估源码授权约束，外部部署不纳入已证明范围。 | 示例保护检查记录。 |

专业审计记录的保护与控制：

- 未记录额外保护或控制。

- 未记录反证，不能据此推定不存在反证。

矛盾事实及裁决引用：

- 未记录矛盾事实。
- 裁决未引用矛盾项。

独立反方主张：上层中间件可能已经校验资源归属。；处置：已反驳。

- 示例中间件只建立登录主体，不读取资源归属。

阻断问题：

- 无记录中的阻断问题。

#### 复现设计（未执行）

环境要求：明确授权的本机隔离环境，具备两个测试账户。

- 使用独立测试数据，已知各自资源归属。

1. 记录账户甲读取自己测试资源的基线。
2. 用账户乙请求同一测试资源，对照响应。

安全行为预期：账户乙被拒绝且响应不包含账户甲的数据。

漏洞行为预期：账户乙收到仅应由账户甲访问的测试资源。

#### 动态测试实际记录

执行状态：已跳过。未提供动态测试环境，已跳过。

本项没有已绑定的动态测试包；上文复现步骤仅是设计，不是执行记录。

#### 独立复核与最终裁定

**正方主张**：已证明

会话：example-AFFIRMATIVE；复核模式：FULL；事实包摘要：aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa。

- 示例对象授权路径需要补齐。

正方沿参数、查询、响应验证对象权限缺失。

主张依据：

- E0
- E1

实际复核证据：

- E0
- E1

复核缺口：

- 运行条件尚未验证。

运行证据判断：不适用；没有动态环境，本次只复核静态证据。

- 没有参与判断的动态测试包。

**反方反例**：已反驳

会话：example-NEGATIVE；复核模式：FULL；事实包摘要：aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa。

- 示例对象授权路径需要补齐。

反方检查中间件和全局拦截，示例中没有足以推翻静态结论的证据。

主张依据：

- E0
- E1

实际复核证据：

- E0
- E1

复核缺口：

- 运行条件尚未验证。

运行证据判断：不适用；没有动态环境，本次只复核静态证据。

- 没有参与判断的动态测试包。

**裁定方**：真实漏洞

会话：example-MODERATOR；复核模式：FULL；事实包摘要：aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa。

- 示例对象授权路径需要补齐。

裁定采纳静态结论，明确未取得动态复现证据。

主张依据：

- E0
- E1

实际复核证据：

- E0
- E1

复核缺口：

- 运行条件尚未验证。

运行证据判断：不适用；没有动态环境，本次只复核静态证据。

- 没有参与判断的动态测试包。

最终理由：示例通过独立三方静态复核，运行环境仍未知。

#### 修复建议与回归标准

将主体和租户约束纳入查询与响应前的授权判断。

1. **资源查询与响应返回之间**：按当前主体和租户限制查询。 原因：将权限判断绑定到实际资源。

临时缓解：

- 限制受影响入口的访问范围。

兼容性与实施注意：

- 保留显式获授权的管理员路径。

| 用例类型 | 场景 | 通过标准 |
|---|---|---|
| 安全回归 | 非所有者读取另一账户的测试资源。 | 拒绝请求，响应不含资源内容。 |
| 正常功能回归 | 所有者读取自己的测试资源。 | 正常返回合法资源。 |

#### 风险评分依据

CVSS 3.1：`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`；6.5 / MEDIUM。

示例假设已登录账户能跨账户读取敏感资源。

评分假设：

- 影响仅限当前示例资源的机密性。

评分证据：

- E0
- E1

#### 交付缺口与证据溯源

- 本项所需内容字段已提供；字段齐全不代表证据必然正确。

- 原始候选：`reports/example/input.json` /candidates/0/finding（SHA-256：`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`）
- 独立裁决：`reports/example/adjudication.json` /decisions/0（SHA-256：`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`）
- 运行记录：`reports/example/runtime.json` /packets（SHA-256：`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`）
- 最终路由：`reports/example/routing.json` /findings/0（SHA-256：`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`）
- 评分制品：`reports/example/cvss.json` /assessments/0（SHA-256：`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`）
- 原始候选对象 SHA-256：`624d1eb51c9e2d0a18efe9a3119b343c4f5f3140142e45387d84fb41494361b5`
- reports/example/web-source-auditor.json
- 原始候选制品：{"path":"reports/example/source.json","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
- AFFIRMATIVE：`reports/example/AFFIRMATIVE.json` /findings/0（SHA-256：`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`）
- NEGATIVE：`reports/example/NEGATIVE.json` /findings/0（SHA-256：`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`）
- MODERATOR：`reports/example/MODERATOR.json` /findings/0（SHA-256：`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`）
