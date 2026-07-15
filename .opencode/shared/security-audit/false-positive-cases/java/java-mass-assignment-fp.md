# False-Positive Patterns: java-mass-assignment

- **language**: java
- **skill**: `java-mass-assignment`
- **weakness**: `mass-assignment`
- **dimension**: D9
- **source**: vuln_skill_builder `analysis/false-positive-patterns.yaml`

## Not a vulnerability

### `dedicated-safe-dto`
- Pattern: request type is DTO with only intended fields; entity mapped explicitly
- Reason: attacker cannot set privilege/financial fields

### `json-read-only-sensitive`
- Pattern: sensitive fields have @JsonProperty(READ_ONLY) or @JsonIgnore on write path
- Reason: Jackson will not bind those properties from request

### `initbinder-allowlist-complete`
- Pattern: setAllowedFields lists only safe form fields for that command object
- Reason: DataBinder rejects unexpected privilege parameters

### `admin-only-by-design`
- Pattern: endpoint requires admin and only admins may set role; no lower-privilege entry
- Reason: not privilege escalation via over-posting (still document if mis-scoped)

### `test-only-binding`
- Pattern: ModelAttribute/RequestBody entity only in test sources
- Reason: not production reachable

### `response-entity-only`
- Pattern: entity used only as response body, never as write binding target
- Reason: may be data exposure, not mass assignment write

## Needs deeper review

### `modelattribute-user-entity`
- Pattern: @ModelAttribute UserEntity
- Reason: classic spring-mvc-entity-binding

### `requestbody-account`
- Pattern: @RequestBody Account with balance/role
- Reason: jackson-requestbody-sensitive-fields

### `beanutils-request-to-entity`
- Pattern: BeanUtils.copyProperties(dto, entity) without full ignore list
- Reason: patch-without-allowlist / transfer sink

### `entity-as-controller-param`
- Pattern: controller parameter type is @Entity class
- Reason: entity-as-dto

### `nested-roles-json`
- Pattern: User.roles collection deserializable
- Reason: nested-binding-privilege

### `sdr-exported-entity`
- Pattern: RepositoryRestResource on User/Account repository
- Reason: full entity write surface via HTTP
