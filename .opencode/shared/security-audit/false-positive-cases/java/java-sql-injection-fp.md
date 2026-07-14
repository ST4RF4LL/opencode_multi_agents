# False-Positive Patterns: java-sql-injection

- **language**: java
- **skill**: `java-sql-injection`
- **weakness**: `sql-injection`
- **dimension**: D1
- **source**: vuln_skill_builder `analysis/false-positive-patterns.yaml`

## Not a vulnerability

### `constant-sql-prepared`
- Pattern: PreparedStatement/JdbcTemplate with constant SQL and bound params only
- Reason: user input cannot change query structure

### `mybatis-hash-only`
- Pattern: MyBatis #{} placeholders only, no ${} for untrusted data
- Reason: parameter binding

### `criteria-api-metamodel`
- Pattern: JPA Criteria API with static metamodel paths
- Reason: no string-built SQL structure from user input

### `identifier-allowlist`
- Pattern: sort/column mapped through immutable allowlist/enum
- Reason: attacker selects among fixed safe identifiers only

## Needs deeper review

### `prepared-but-concat`
- Pattern: prepareStatement(sql) where sql includes + / format / append
- Reason: false sense of safety

### `order-by-param`
- Pattern: ORDER BY + request parameter
- Reason: classic identifier injection; value binding does not apply

### `mybatis-dollar`
- Pattern: ${} in mapper XML/annotation
- Reason: substitution; confirm whether value is user-controlled

### `native-query-with-spel`
- Pattern: Spring @Query nativeQuery with SpEL fragments
- Reason: may embed untrusted expressions

### `like-concat`
- Pattern: LIKE '%'+input+'%'
- Reason: often true SQLi if quotes not parameterized

### `wrapper-dao`
- Pattern: custom SqlUtil/DAO execute(String)
- Reason: sink is indirection; expand to real executor

