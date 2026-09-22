> 平台适配说明：以下保留原始模型与证据方法；平台输入的 repository/scope、独立 producer 与结构化 evidence 以 `.opencode/lib/bac/workflow.md` 和 shared input-contract 为准。

# BACAgent ACP model

## Exact tuple

Use only:

`ACP = <D, O, R, AC>`

| Element | Meaning | Allowed representation |
|---|---|---|
| `D` | Database resource | Canonical table or directly corresponding persistence entity name |
| `O` | Operation | `CREATE`, `READ`, `UPDATE`, `DELETE` |
| `R` | Role | Non-empty repository-derived role name |
| `AC` | Intended access control | `NONE`, `VAC`, `HAC`, `VAC+HAC` |

`R` identifies the role whose policy is being modeled. `AC` identifies the required control type.

## Control semantics

- `NONE`: the operation is intentionally public for role `R`; no VAC or HAC is required.
- `VAC`: the operation requires vertical access control that establishes the appropriate identity, role, or privilege represented by `R`.
- `HAC`: the operation requires a direct horizontal owner check between the acting user and the database resource.
- `VAC+HAC`: both controls are required.

Do not add API, route, path, endpoint, permission code, scope, condition, effect, evidence, confidence, or implementation state to the tuple.

## Intended versus implemented

The finalized tuple represents intended policy. Observed checks are evidence and may be defective.

Use:

`finding = intended AC - implemented controls on a reachable path`

Examples:

- Intended `VAC+HAC`, implemented `VAC`: possible missing-owner-check vulnerability.
- Intended `VAC`, implemented `NONE`: possible vertical access-control vulnerability.
- Intended `NONE`, implemented `NONE`: no BAC mismatch.

Do not infer `NONE` only because all observed paths lack checks. Consider semantic evidence and the possibility of a systematic vulnerability.

## Evidence strength

Use the following default ordering:

1. Explicit access-control policy or configuration tied to the resource and operation.
2. Verified framework/platform semantics and role mapping.
3. Multiple consistent implementations for the same resource, operation, and role.
4. Direct schema ownership relation plus owner comparisons elsewhere.
5. API path, method name, signature, and comment.
6. General business-name semantics.

LLM interpretation alone is never sufficient evidence for a finalized tuple.

Recommended confidence bands:

- `0.90-1.00`: explicit policy or multiple independent, consistent, high-quality evidence sources.
- `0.75-0.89`: strong code evidence with minor ambiguity.
- `0.50-0.74`: plausible but incomplete; normally keep unresolved.
- `<0.50`: do not finalize.

## Boundary rules

- Model database resources only.
- Do not model files, object storage, cache keys, messages, external-service objects, virtual aggregates, or fields as `D`.
- Do not collapse tenant, organization, department, region, sharing, delegation, workflow state, or field-level rules into HAC.
- A permission code is not a role unless its mapping is recovered.
- Authentication or role checks may support VAC, but identity propagation alone is not a control.
- A foreign key to a user is ownership evidence, not proof that every operation requires HAC.
- A public read can be `NONE` even when create, update, and delete require VAC or HAC.

## JSON contract

Use this envelope. Metadata remains outside `tuple` and therefore does not extend the paper model.

```json
{
  "schema_version": "1.0",
  "repository": {
    "root": "/absolute/repository/path",
    "revision": "git-revision-or-unknown"
  },
  "coverage": {
    "modules_inspected": [],
    "modules_uninspected": [],
    "entrypoints_discovered": 0,
    "database_operations_discovered": 0,
    "database_operations_mapped": 0,
    "known_gaps": []
  },
  "quadruples": [
    {
      "tuple": {
        "D": "Order",
        "O": "READ",
        "R": "USER",
        "AC": "VAC+HAC"
      },
      "confidence": 0.96,
      "inference_basis": "Concise explanation",
      "evidence": [
        {
          "kind": "owner-check",
          "location": "src/main/java/example/OrderService.java:42",
          "detail": "Compares current user id with order owner id"
        }
      ],
      "covered_entrypoints": ["GET /orders/{id}"],
      "implemented_controls": [
        {
          "entrypoint": "GET /orders/{id}",
          "controls": ["VAC", "HAC"]
        }
      ],
      "findings": []
    }
  ],
  "unresolved": [],
  "out_of_model": [],
  "limitations": []
}
```

Every finalized tuple must have at least one evidence item and a confidence value from `0` to `1`.

## Markdown tuple table

Use these columns:

| D | O | R | AC | Confidence | Primary evidence |
|---|---|---|---|---:|---|

Keep findings and implementation details in separate sections so they are not mistaken for tuple dimensions.
