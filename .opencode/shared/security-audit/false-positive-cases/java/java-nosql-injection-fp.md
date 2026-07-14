# False-Positive Patterns: java-nosql-injection

- **language**: java
- **skill**: `java-nosql-injection`
- **weakness**: `nosql-injection`
- **dimension**: D1
- **source**: vuln_skill_builder `analysis/false-positive-patterns.yaml`

## Not a vulnerability

### `filters-eq-constant-field`
- Pattern: Filters.eq / Criteria.where with constant field name and bound scalar value
- Reason: user input cannot introduce operators or change query structure

### `derived-spring-data-method`
- Pattern: Spring Data MongoDB derived query method (findByName)
- Reason: framework binds values safely

### `constant-document`
- Pattern: Document/BasicDBObject with only constant keys and constant or bound scalars
- Reason: no external structure control

### `field-allowlist-fixed-op`
- Pattern: user selects field from allowlist; operator fixed in code
- Reason: attacker chooses among fixed safe fields only

## Needs deeper review

### `document-parse-any`
- Pattern: Document.parse / BasicDBObject.parse
- Reason: high-risk sink; confirm input trust boundary

### `request-body-as-filter`
- Pattern: @RequestBody Map/JsonNode/Document used in find/update
- Reason: classic operator injection surface

### `where-clause`
- Pattern: $where or Filters.where
- Reason: server-side JS; treat as critical if user-influenced

### `basicquery-string`
- Pattern: new BasicQuery(string)
- Reason: equivalent to parsing query JSON

### `string-concat-json`
- Pattern: building query JSON with + / format / append
- Reason: structure and quote injection

### `wrapper-dao`
- Pattern: custom MongoUtil/QueryHelper execute(Document|String)
- Reason: sink is indirection; expand to real executor

