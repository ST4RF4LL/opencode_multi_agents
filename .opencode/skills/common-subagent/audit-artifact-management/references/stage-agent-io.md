# Stage/Agent input and output envelopes

The normative registry is
`../contracts/stage-agent-contracts.json`. This reference explains the common
wire format; a contract's artifact and payload field lists remain authoritative.

## Input

Every input JSON has exactly these fields:

```json
{
  "schema_version": 1,
  "contract_id": "P04_FOCUS_EXECUTION.java-source-auditor",
  "stage_id": "P04_FOCUS_EXECUTION",
  "direction": "INPUT",
  "audit_id": "audit-id",
  "round": 1,
  "agent_name": "java-source-auditor",
  "agent_session_id": "java-fa-001-sink-coverage-r1",
  "scope_binding": {
    "state": "FROZEN",
    "scope_digest": "64 lowercase hex characters"
  },
  "artifact_bindings": [
    {
      "artifact_type": "focus-work-packet",
      "path": "reports/coverage/work-packets/packet.json",
      "sha256": "64 lowercase hex characters",
      "media_type": "application/json",
      "json_pointer": null
    }
  ],
  "payload": {
    "focus_area_id": "FA-001",
    "assignment_id": "FA-001-java-base",
    "discovery_track": "coverage",
    "audit_strategy": "sink-driven",
    "assigned_file_ids": [],
    "assigned_function_ids": [],
    "assigned_catalog_ids": [],
    "depth": "comprehensive"
  },
  "constraints": [
    "Do not execute target code."
  ],
  "envelope_digest": "computed by seal-stage-agent-envelope.mjs"
}
```

All contract-required artifact types must be present. Payload keys must be
exactly the contract's required fields plus any declared optional fields.
Unregistered keys are rejected.

## Output

Every output JSON has exactly these fields:

```json
{
  "schema_version": 1,
  "contract_id": "P04_FOCUS_EXECUTION.java-source-auditor",
  "stage_id": "P04_FOCUS_EXECUTION",
  "direction": "OUTPUT",
  "audit_id": "audit-id",
  "round": 1,
  "agent_name": "java-source-auditor",
  "agent_session_id": "java-fa-001-sink-coverage-r1",
  "scope_binding": {
    "state": "FROZEN",
    "scope_digest": "64 lowercase hex characters"
  },
  "input_envelope_digest": "exact sealed input envelope digest",
  "status": "COMPLETE",
  "artifact_bindings": [
    {
      "artifact_type": "focus-audit-result",
      "path": "reports/vulnerability-mining/java-source-auditor.java-fa-001-sink-coverage-r1.audit-report.json",
      "sha256": "64 lowercase hex characters",
      "media_type": "application/json",
      "json_pointer": null
    }
  ],
  "payload": {
    "focus_area_id": "FA-001",
    "assignment_id": "FA-001-java-base",
    "discovery_track": "coverage",
    "audit_strategy": "sink-driven",
    "coverage_state": "PASS",
    "finding_ids": [],
    "ledger_decision_refs": [],
    "gaps": []
  },
  "gaps": [],
  "envelope_digest": "computed by seal-stage-agent-envelope.mjs"
}
```

`COMPLETE` requires all required artifact types and zero gaps. `PARTIAL`,
`BLOCKED`, `FAILED`, and `NOT_APPLICABLE` require at least one gap:

```json
{
  "gap_id": "GAP-FA-001-001",
  "category": "source-unreadable",
  "description": "A required source file could not be parsed.",
  "blocking": true,
  "evidence_refs": ["parser-capabilities"]
}
```

An output can be consumed only after its envelope and bound input validate.
Aggregate finalization uses `verify-stage-agent-handoffs.mjs`, which derives
Focus coverage/discovery expectations from the sealed Focus Area manifest.
