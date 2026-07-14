# Real-World SQL Injection Case Library

来源：`ghsa-skill-builder` 的 GHSA（`pip_details_89.json` / `pip_details_injection.json`）与 HackerOne（`h1_by_category/sqli.json`）。

目标：沉淀**可迁移根因模式**，并映射到 Java 审计与 Joern 规则（见 `pattern-to-joern.yaml`、`rules/joern/derived/`）。  
原始 payload / 域名 / 接口路径不可直接复用。

---

### Case R1: ormar — 聚合函数列名未经校验进入原生 SQL 文本 (CVE-2026-26198, GHSA-xxh2-68g9-8jqr, CVSS 9.8)

**Source**: GHSA / `pip_details_89.json`

**Root Cause**: ORM 将用户传入的**列名/标识符**直接嵌入 `sqlalchemy.text()`；`min()`/`max()` 跳过字段存在性校验。

**Source → Sink**:
- **Source**: API 查询参数 `column`（如 `/items/stats?metric=max&column=...`）
- **Sink**: `sqlalchemy.text(f"{alias}{self.field_name}")` → `func.max/min(...)`
- **Sanitization Gap**: 仅对 `sum`/`avg` 做 `is_numeric`；`min`/`max` 无白名单

**Vulnerable Pattern** (Python origin):
```python
return sqlalchemy.text(f"{alias}{self.field_name}")  # unsanitised
# await Item.objects.max(user_controlled_column)
```

**Java 等价模式**:
- `ORDER BY` / `GROUP BY` / SELECT 列表列名来自 `@RequestParam`
- MyBatis `${column}` / `${sort}`
- `createNativeQuery("SELECT " + col + " FROM ...")`
- Criteria/QueryDSL 用字符串 path 而非 metamodel

**Why scanners miss it**:
- 标准 taint 常把“列名参数”当非敏感
- ORM 安全假象：调用方以为 ORM 已参数化

**How to detect (Java)**:
1. 定位动态标识符拼接与 `${}`
2. 确认无 enum/allowlist 映射
3. 运行 Joern: `derived/dynamic-identifier.sc`

**Joern rule**: `rules/joern/derived/dynamic-identifier.sc`  
**Similar**: CVE-2024-12909, H1 path-param SQLi patterns

---

### Case R2: asyncmy / PyMySQL class — 只转义 dict value、不转义 dict key (CVE-2025-65896, GHSA-qhqw-rrw9-25rm, CVSS 9.8)

**Source**: GHSA / `pip_details_injection.json` + [asyncmy#134](https://github.com/long2ice/asyncmy/issues/134)

**Root Cause**: `escape_dict` 仅对 **value** 做 quote，**key** 原样进入 SQL 结构（同 CVE-2024-36039 PyMySQL）。

**Source → Sink**:
- **Source**: 用户可控的 dict/map 键（字段名、更新列名）
- **Sink**: SQL 构造中直接拼接 map key
- **Sanitization Gap**: “做了 escape”但对象层级不完整

**Vulnerable Pattern** (origin):
```python
for k, v in val.items():
    quoted = escape_item(v, charset, mapping)  # value only
    n[k] = quoted  # key unescaped
```

**Java 等价模式**:
- `Map<String,Object>` 的 key 拼进 `SET col=?` / `WHERE col=?` 的 **col** 部分
- MyBatis `<foreach>` 用 `${key}` 而非列白名单
- 动态 UPDATE builder：`for (e : map) sql.append(e.getKey()).append("=?,")`
- JSON/body 反序列化后的字段名直接进 SQL

**Why scanners miss it**:
- 看见 escape/quote 调用就降级风险
- key 与 value 的 taint 角色不同，默认模型常只盯 value

**How to detect (Java)**:
1. 找 map/entry 迭代拼 SQL
2. 确认 key 是否 allowlist
3. 运行 Joern: `derived/map-key-to-sql.sc`

**Joern rule**: `rules/joern/derived/map-key-to-sql.sc`  
**Similar**: CVE-2024-36039 (PyMySQL)

---

### Case R3: llama-index-packs-finchat — Agent/工具把不可信 SQL 直接执行 (CVE-2024-12909, GHSA-x48g-hm9c-ww42, CVSS 10.0)

**Source**: GHSA / `pip_details_89.json`

**Root Cause**: `database_agent.run_sql_query` 执行来自 Agent/用户链路的任意 SQL；可经 PostgreSQL large object 等能力升级到 RCE。

**Source → Sink**:
- **Source**: LLM/Agent 输出或工具参数中的 SQL 文本
- **Sink**: 数据库执行接口（任意查询）
- **Sanitization Gap**: 无 SQL 允许列表/只读约束/语句类型限制

**Java 等价模式**:
- 管理后台“自定义查询/报表”接口直接 `jdbcTemplate.query(userSql)`
- AI Copilot / Agent Tool 调用 `Statement.execute(sqlFromModel)`
- 脚本引擎把生成 SQL 交给 JDBC

**Why scanners miss it**:
- Source 不是典型 HTTP getParameter，而是 LLM/工具输出
- 业务上常被标成“内部功能”

**How to detect (Java)**:
1. 搜索“执行任意 SQL”API、agent tool、report builder
2. 确认 SQL 字符串是否完全外部可控
3. 运行 Joern: `derived/raw-sql-execution.sc`

**Joern rule**: `rules/joern/derived/raw-sql-execution.sc`

---

### Case R4: Django ORM — Q 对象 `_connector` 字符串格式化注入 (H1 #3335709, Critical)

**Source**: HackerOne / `h1_by_category/sqli.json`

**Root Cause**: ORM 内部用不安全字符串格式化插入 query connector；攻击者通过 `_connector` 键控制 WHERE 连接符，绕过参数化表象。

**Source → Sink**:
- **Source**: 反序列化/构造 Q 对象时的 `_connector`（或等价内部字段）
- **Sink**: `WhereNode.as_sql` 等 SQL 编译路径
- **Sanitization Gap**: 内部结构字段被当作可信

**Java 等价模式**:
- 查询 DSL/过滤器 JSON：`{"op":"OR' --","field":...}` 拼进 SQL
- 动态 `AND`/`OR`/`NOT` 来自请求体
- Specification/Predicate 构建使用字符串 operator

**Why scanners miss it**:
- sink 在框架/编译层；应用层只有“过滤对象”
- 标准规则不覆盖 connector/operator 注入

**How to detect (Java)**:
1. 找 filter DTO → SQL/HQL 编译
2. operator/connector 是否白名单
3. 运行 Joern: `derived/operator-connector-inject.sc`

**Joern rule**: `rules/joern/derived/operator-connector-inject.sc`  
**Similar**: H1 #3292573 FilteredRelation

---

### Case R5: Django — FilteredRelation / 动态 relation 条件注入 (H1 #3292573, Critical)

**Source**: HackerOne / `h1_by_category/sqli.json`

**Root Cause**: `FilteredRelation` / `select_related` 路径上用户数据进入 relation 过滤条件字符串。

**Java 等价模式**:
- 动态 join on 条件字符串
- Hibernate `@Filter` / 动态 fetch profile 名称或条件来自用户
- MyBatis 动态 `<if>` 中 `${}` 条件片段

**Joern rule**: `derived/dynamic-filter-fragment.sc`（与 identifier 规则交叉）

---

### Case R6: MTN Group — URL 路径参数进入 SQL (H1 #2958619 / #2633959, Critical)

**Source**: HackerOne / `h1_by_category/sqli.json`

**Root Cause**: 路径中的 `customerId`/组织号等直接参与 SQL，单引号触发语法错误并可进一步利用。

**Source → Sink**:
- **Source**: URL path segment（非 query string）
- **Sink**: 后端 SQL 查询

**Java 等价模式**:
- `@PathVariable String id` → 字符串拼接 SQL
- `getPathInfo()` / 路由变量进 DAO

**Why scanners miss it**:
- 只扫 query/body，忽略 path variable source

**How to detect (Java)**:
1. PathVariable/pathInfo 标为 source
2. 到 SQL sink 的数据流
3. 运行 Joern: `derived/path-param-to-sql.sc`

**Joern rule**: `rules/joern/derived/path-param-to-sql.sc`  
**Similar**: H1 #2266081 (blind via URI path), #2209130 invite_code

---

### Case R7: Mars / Mozilla — 业务参数上的 error/time-based 盲注 (H1 #3293803, #3277276, #2266081, #2209130)

**Source**: HackerOne / `h1_by_category/sqli.json`

**Root Cause**: 主题名、业务参数、invite_code 等进入查询；可能无回显，需时间/布尔差分确认。

**可迁移经验**:
- 无 error 回显 ≠ 无注入
- 未认证 POST + 缺 CSRF 扩大利用面
- 验证应基于**目标路径**生成，不复用历史 payload

**Java 检测要点**:
- L2 静态路径成立后，用 `validation/playbook.yaml` 做差分验证
- 不把 generic 500 单独当 strong evidence

**Joern rule**: 复用 `source-to-sink.sc` + `path-param-to-sql.sc`；验证层见 `validation/`

---

### Case R8: IBM 端点 SQLi (H1 #3578842 / #2830573, Critical)

**Source**: HackerOne（公开摘要有限）

**可迁移经验**:
- 大型站点仍存在经典参数拼接
- 披露摘要不足时，仍应按 L1 sink + L2 数据流标准流程审计，不依赖报告细节

**Joern rule**: 基线 `locate-sinks.sc` + `source-to-sink.sc`

---

## Pattern Index → Joern

| Case | Pattern ID | Joern script |
|------|------------|--------------|
| R1 | dynamic-identifier | `derived/dynamic-identifier.sc` |
| R2 | map-key-to-sql | `derived/map-key-to-sql.sc` |
| R3 | raw-sql-execution | `derived/raw-sql-execution.sc` |
| R4 | operator-connector-inject | `derived/operator-connector-inject.sc` |
| R5 | dynamic-filter-fragment | `derived/dynamic-filter-fragment.sc` |
| R6 | path-param-to-sql | `derived/path-param-to-sql.sc` |
| R7-R8 | classic source-to-sink | `source-to-sink.sc` |

完整映射与提炼说明：`references/pattern-to-joern.yaml`。
