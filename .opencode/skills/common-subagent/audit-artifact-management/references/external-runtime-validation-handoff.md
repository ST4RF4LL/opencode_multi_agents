# External runtime-validation handoff

This repository is a static producer by default. It does not execute a request
unless the user explicitly invokes the separately permissioned localhost
dynamic-validation sidecar described below.

The request schema and result schema live under the
`finding-evidence-contract/schemas/` directory. The shared implementation is
`finding-evidence-contract/scripts/external-runtime-validation-contract.mjs`.

## Producer boundary

The static project may export a request only after it has:

- a valid Finding v2 object with attack-surface v1 facts;
- an independent `SUPPORTED_STATIC` or `INCONCLUSIVE` decision;
- immutable finding and adjudication artifact bindings;
- explicit runtime proof gaps; and
- an isolated-test-only safety policy.

The request policy always forbids production targets, third-party targets, real
credentials, unauthorized persistence, and data destruction. Network access is limited to
denied, loopback-only, or test-fixture-only operation.

## Explicit localhost Web sidecar

`dynamic-vulnerability-validator` may consume a valid request only when the
user explicitly asks for dynamic validation and supplies a loopback URL, two
test accounts, login instructions, and cleanup instructions. It accepts catalog
types whose `applies_to` includes `web`, uses the controller-selected
`chrome-devtools-mcp`, and writes a digest-bound target/result companion under
`reports/validation-handoff/runtime/`. `JW-INJECT-06` uses the XSS-specific
contract; other Web types use the generic non-destructive Web contract.

A safe marker stored in authorized test data solely to prove stored XSS is not
the prohibited persistence category. Backdoors, footholds, unrelated state,
and payload retention beyond the authorized test are still forbidden. Cleanup
must be attempted; failure is preserved as residual exposure rather than used
to erase valid execution evidence.

## Downstream result

A separately authorized project may return `SUPPORTED_RUNTIME`, `REJECTED`,
`INCONCLUSIVE`, or `NOT_RUN`. The result binds to the request digest and carries
the validator identity, methods, sanitized evidence artifacts, observations,
counterevidence, residual gaps, and an explicit safety attestation.

The static project may validate and archive the packet. It must not
automatically rewrite the original finding, adjudication manifest, chain
manifest, or final report. Import and promotion semantics belong to the later
runtime-validation project.
