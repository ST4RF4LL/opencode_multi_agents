---
name: finding-adjudication
description: Independently adjudicate accepted Finding v2 coverage candidates before attack-chain construction or final reporting. Use when a candidate must be checked for real framework semantics, reachability, guards, a tested counterclaim, and an explicit SUPPORTED_STATIC, SUPPORTED_RUNTIME, REJECTED, INCONCLUSIVE, or RECLASSIFIED outcome.
---

# Finding Adjudication

Use this skill after Coverage v3 has accepted and Ledger-attested Finding v2
artifacts. It is a separate semantic decision, not a second coverage pass and
not the final third-party report review.

## Input and output

Build the trusted candidate set from the frozen Plan, Ledger, and structural
artifact:

```sh
node .opencode/skills/common-subagent/finding-adjudication/scripts/build-adjudication-input.mjs \
  --audit-id <audit-id> \
  --plan reports/coverage/coverage-plan.<audit-id>.json \
  --ledger reports/coverage/<audit-id>/ledger/coverage-ledger.jsonl \
  --structural reports/coverage/coverage-structural-v1.<audit-id>.json \
  --output reports/adjudication/finding-input.<audit-id>.r<round>.json
```

Create one independent decision for every input candidate, then validate it:

```sh
node .opencode/skills/common-subagent/finding-adjudication/scripts/validate-finding-adjudication.mjs \
  --input reports/adjudication/finding-input.<audit-id>.r<round>.json \
  --adjudication reports/adjudication/security-finding-adjudicator.<audit-id>.r<round>.json
```

The adjudication manifest must account for each input candidate exactly once.
Only `SUPPORTED_STATIC` and `SUPPORTED_RUNTIME` enter the subsequent
truth-validation intake. They still cannot reach final attack chains or report
synthesis until validation-routing returns `TRUE_POSITIVE`. `CANDIDATE` is
never a final vulnerability state.

## Required semantic work

For every candidate:

1. Re-open the frozen source/config location and bind the decision to the
   candidate fact indexes.
2. Resolve the actual framework/library version, API overload, configuration
   precedence, and deployment condition where they affect the claim.
3. Establish source to semantic sink/configuration to security effect, or
   explicitly state why that path fails.
4. Evaluate local, inherited, global, and deployment guards separately.
5. Review all 13 fixed attack-surface fields. Record the exact field set,
   evidence, rationale, limitations, and one disposition: `ACCEPTED`,
   `LIMITED`, `CONTRADICTED`, or `UNRESOLVED`. A supported decision permits only
   `ACCEPTED` or evidence-backed `LIMITED`; an inconclusive decision requires
   `UNRESOLVED`.
6. Test a counterclaim. A supporting decision requires that counterclaim to be
   refuted; a rejection requires it to be supported; uncertainty requires an
   explicit unresolved question.
7. Do not assign a final CVSS score here. Record evidence and outcome; later
   scoring is a separate deterministic step. After truth routing, the
   orchestrator supplies vectors only for routing `TRUE_POSITIVE`, including
   `validation_routing_digest`, to `build-cvss-assessment.mjs --routing ...`;
   the script, not an agent, derives the score and severity.

Use the framework checklists in `references/framework-semantic-models.md` for
JWT, object storage paths, logging, mass assignment, Spring RBAC, Actuator,
CORS, and URL/SSRF/redirect claims.

## Boundaries

- Do not modify the candidate, Ledger, Coverage Plan, or source repository.
- Do not turn a blind or seeded candidate into coverage closure.
- Do not call a potential chain `SUPPORTED_*` when a required transition is
  unknown; preserve the uncertainty for the chain gate.
- Do not call external `vuln_judger`; local truth validation belongs to
  `vulnerability-validator` after this preliminary adjudication.
