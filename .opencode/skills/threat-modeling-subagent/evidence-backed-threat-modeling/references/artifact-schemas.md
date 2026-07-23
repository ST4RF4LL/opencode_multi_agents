# Semantic audit artifact schemas

## Threat model

Write `tmp/<audit_id>/recon/threat-model.json`:

```json
{
  "schema_version": 1,
  "audit_id": "audit-id",
  "scope_digest": "sha256",
  "mode": "bootstrap|bootstrap-then-interview",
  "system_context": "...",
  "assets": [{"asset_id":"ASSET-001","name":"...","sensitivity":"low|medium|high|critical","evidence":[]}],
  "actors": [{"actor_id":"ACTOR-001","type":"remote_unauth|remote_auth|local_user|local_admin|supply_chain|insider|malicious_content|compromised_tool|peer_agent|knowledge_source|model_provider|tenant_user","capabilities":[],"evidence":[]}],
  "trust_boundaries": [{"trust_boundary_id":"TB-001","from":"...","to":"...","evidence":[]}],
  "entry_points": [{"entry_point_id":"EP-001","name":"...","trust_boundary_ids":["TB-001"],"reachable_asset_ids":["ASSET-001"],"inventory_ids":[],"evidence":[]}],
  "threats": [{"threat_id":"T-001","outcome":"...","actor_ids":["ACTOR-001"],"entry_point_ids":["EP-001"],"trust_boundary_ids":["TB-001"],"asset_ids":["ASSET-001"],"dimensions":["D1"],"impact":"high","likelihood":"possible","status":"unmitigated","controls":[],"evidence":[],"provenance_tags":["code-verified"]}],
  "deprioritized": [{"entry_point_id":"EP-001","threat_class":"repudiation","reason":"...","evidence":[]}],
  "history_clusters": [{"cluster_id":"HC-001","entry_point_ids":["EP-001"],"weakness_class":"...","asset_ids":["ASSET-001"],"evidence":[],"sibling_locations":[]}],
  "entry_point_coverage": [{"entry_point_id":"EP-001","status":"THREAT|DEPRIORITIZED|GAP","threat_ids":["T-001"],"reason":null,"evidence":[]}],
  "open_questions": [{"question_id":"Q-001","question":"...","blocking":true,"status":"open|resolved","evidence":[]}],
  "provenance": {"target":"...","commit":"...","inputs":[],"owner":null},
  "manifest_digest": "sha256"
}
```

Use outcome-oriented threats. Evidence may be empty only for STRIDE gap-fill threats; provenance must still explain their derivation. A complete semantic audit cannot contain `GAP` entry-point coverage or an open blocking question.

## Focus Areas

Write `tmp/<audit_id>/recon/focus-areas.json`:

```json
{
  "schema_version": 1,
  "audit_id": "audit-id",
  "scope_digest": "sha256",
  "threat_model_digest": "sha256",
  "required_lenses": ["sink-driven","control-driven","config-driven"],
  "focus_areas": [{
    "focus_area_id":"FA-001",
    "title":"...",
    "description":"...",
    "priority":"critical|high|medium|low",
    "entry_point_ids":["EP-001"],
    "threat_ids":["T-001"],
    "trust_boundary_ids":["TB-001"],
    "asset_ids":["ASSET-001"],
    "history_cluster_ids":["HC-001"],
    "required_discovery_tracks":["coverage","blind","seeded-variant"],
    "assignments":[{
      "assignment_id":"FA-001-java-base",
      "agent_name":"java-source-auditor",
      "language":"java",
      "file_function_domain":"base",
      "catalog_domain":"java",
      "file_ids":[],
      "function_ids":[],
      "catalog_ids":[]
    }],
    "context_file_ids":[],
    "context_function_ids":[]
  }],
  "gaps": [],
  "manifest_digest": "sha256"
}
```

An assignment with all three ID arrays empty is invalid. For the same `agent_name + file_function_domain + catalog_domain`, primary entity IDs must not repeat across Focus Areas. Context IDs may overlap and never close accounting coverage.

Valid discovery tracks are `coverage`, `blind`, and `seeded-variant`. The structural audit report is the `coverage` track; the other tracks write `*.discovery.json` and cannot close deterministic coverage.
