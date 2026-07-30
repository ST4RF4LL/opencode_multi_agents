# Framework semantic models

Use these as minimum checks; record the actual version/API/config evidence in
the adjudication decision.

| Claim | Require before supporting | Reject or retain inconclusive when |
|---|---|---|
| JWT algorithm/key | Actual dependency version and invoked overload, key source, verification path, claims enforcement | Algorithm is inferred only from comments, parse-only code, or an unused path |
| Object storage path | Storage API semantics, bucket/key boundary, output behavior and attacker-controlled key | A key string is assumed to be a local filesystem path without a filesystem sink |
| Log injection | User input reaches a real logger/audit sink and affects a security-relevant record | Evidence is only a database note, DTO field, or non-logging persistence |
| Mass assignment | Broad bind/copy, sensitive field, and persistence path | DTO plus explicit allowlisted setters/mapper breaks the claimed path |
| Spring RBAC | Registration/default role/resource relationship, authorities, route decision and mutation path | A route or role name is treated as proof without the complete permission graph |
| Actuator | Boot version, endpoint enablement, web exposure, profile, management port, and applicable security chain | Endpoint exposure is deployment-unknown |
| CORS | Origin rule, credentials/token transport, SameSite, preflight, sensitive response, and deployment topology | The chain assumes browser credential sending or response readability without evidence |
| URL/SSRF/redirect | Attacker value reaches an HTTP client, redirect/location response, or browser navigation | A DTO/config string is treated as a network or redirect sink without one |
