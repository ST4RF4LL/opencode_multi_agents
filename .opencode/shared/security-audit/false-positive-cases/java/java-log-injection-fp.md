# False-Positive Patterns: java-log-injection

- **language**: java
- **skill**: `java-log-injection`
- **weakness**: `log-injection`
- **dimension**: D8
- **source**: vuln_skill_builder `analysis/false-positive-patterns.yaml`

## Not a vulnerability

### `constant-log-message`
- Pattern: logger.info("server started") with no external input
- Reason: no attacker-controlled content

### `structured-json-fields`
- Pattern: JsonTemplateLayout/JsonEncoder binds user data as escaped JSON fields
- Reason: line-oriented CRLF forging largely mitigated (still review XSS if UI renders)

### `sanitized-newlines`
- Pattern: all untrusted log args pass through CRLF/control-char sanitizer before emission
- Reason: effective control for log forging

### `test-only-logging`
- Pattern: logger calls only in test sources
- Reason: not production reachable

## Needs deeper review

### `parameterized-plain-layout`
- Pattern: logger.info("user {}", user) with PatternLayout %msg
- Reason: args may still contain CRLF; not automatic reject

### `auth-login-logs`
- Pattern: login success/failure logs include username/header
- Reason: high-value forge target; verify newline handling

### `header-to-log`
- Pattern: User-Agent / X-Forwarded-For logged directly
- Reason: classic CRLF source

### `mdc-user-fields`
- Pattern: MDC.put("user", requestParam)
- Reason: layout may render into every line

### `wrapper-audit-logger`
- Pattern: AuditLogger.record(String) custom wrapper
- Reason: expand to real logger sink and layout

### `exception-message-loop`
- Pattern: logger.error(ex.getMessage()) where message was user-influenced
- Reason: second-order style log injection

