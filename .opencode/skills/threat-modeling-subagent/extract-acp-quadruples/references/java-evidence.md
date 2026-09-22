> 平台适配说明：以下保留原始模型与证据方法；平台输入的 repository/scope、独立 producer 与结构化 evidence 以 `.opencode/lib/bac/workflow.md` 和 shared input-contract 为准。

# Java repository evidence guide

## Inventory

Inspect:

- Maven and Gradle modules, dependency management, starters, and profiles.
- Spring Boot auto-configuration and conditional beans.
- OpenAPI descriptions, controllers, servlet endpoints, RPC handlers, message listeners, and scheduled jobs.
- SQL migrations, JPA entities, Spring Data repositories, MyBatis mapper interfaces/XML, jOOQ, JDBC, and native SQL.
- Shared platform libraries included as source or binary dependencies.

## Entry points and operations

Find framework entry points including:

- Spring MVC/WebFlux mappings.
- JAX-RS resources.
- Servlet endpoints.
- Dubbo/gRPC or other RPC service implementations.
- Kafka/RocketMQ/RabbitMQ listeners when they reach database operations.
- Scheduled or batch jobs when a role or service identity can be recovered.

Map persistence behavior:

- `save`, `persist`, `insert` → `CREATE` unless the framework performs an upsert that requires path inspection.
- `find`, `get`, `select`, query execution → `READ`.
- dirty-entity flush, `update`, modifying query → `UPDATE`.
- `delete`, `remove` → `DELETE`.

Resolve method names through implementation and SQL. Do not classify solely by name.

## VAC evidence

Look for:

- Spring Security `SecurityFilterChain`, request matchers, `AuthorizationManager`, method security, `@PreAuthorize`, `@Secured`, `@RolesAllowed`, and `PermissionEvaluator`.
- Apache Shiro filters, annotations, Realm implementations, and permission-role mappings.
- Servlet filters, MVC interceptors, WebFlux filters, and AOP advice that can block execution.
- Custom role/permission guards and access-denied branches.
- JWT/session/security-context values flowing into role or permission decisions.

Distinguish:

- token parsing or identity propagation;
- authentication checks;
- role/permission decisions that can deny the operation.

Only the latter two can support a VAC conclusion.

## HAC evidence

Require evidence of a direct ownership relationship:

- current principal identifier;
- resource owner identifier obtained from a database resource or query;
- comparison, join, predicate, or query restriction enforcing equality or an equivalent owner relation;
- denial or exclusion when the relation does not hold.

Examples:

- `currentUser.id == order.userId`
- query predicate `order.user_id = :currentUserId`
- repository method whose resolved query constrains both resource id and owner id

Do not classify these as HAC:

- `tenant_id` equality;
- department or organization membership;
- creator used only for display/auditing;
- a `user_id` field with no enforcing comparison;
- request parameter equality without a trusted current-user source.

## Framework composition

Compute controls along each reachable path:

`gateway/platform assumptions + filter chain + interceptor + method annotation + custom guard + ownership predicate`

Account for:

- multiple security filter chains and matcher order;
- `permitAll` and exclusion rules;
- profiles, feature flags, and conditional auto-configuration;
- annotation inheritance and proxy boundaries;
- self-invocation bypass of proxied method security;
- asynchronous context loss;
- internal calls that bypass the public controller;
- generated code, reflection, dynamic proxies, and dynamic SQL.

If platform source or configuration is unavailable, record the dependency and claimed capability as incomplete evidence rather than assuming the control executes.
