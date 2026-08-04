# External runtime-validation handoff

This repository is the static producer. It does not execute the request.

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
credentials, persistence, and data destruction. Network access is limited to
denied, loopback-only, or test-fixture-only operation.

## Downstream result

A separately authorized project may return `SUPPORTED_RUNTIME`, `REJECTED`,
`INCONCLUSIVE`, or `NOT_RUN`. The result binds to the request digest and carries
the validator identity, methods, sanitized evidence artifacts, observations,
counterevidence, residual gaps, and an explicit safety attestation.

The static project may validate and archive the packet. It must not
automatically rewrite the original finding, adjudication manifest, chain
manifest, or final report. Import and promotion semantics belong to the later
runtime-validation project.
