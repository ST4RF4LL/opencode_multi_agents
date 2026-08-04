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
  "security_invariants": [{"invariant_id":"INV-001","statement":"A tenant may access only its own records.","asset_ids":["ASSET-001"],"threat_ids":["T-001"],"enforcement_points":["service ownership check"],"evidence":[],"provenance_tags":["code-verified"]}],
  "assumptions": [{"assumption_id":"ASM-001","statement":"The reverse proxy preserves the authenticated principal.","category":"architecture|deployment|identity|data|dependency|operator|external","status":"VERIFIED|UNVERIFIED|CONTRADICTED","affects_threat_ids":["T-001"],"evidence":[],"provenance_tags":["deployment-unknown"]}],
  "attacker_stories": [{"story_id":"STORY-001","actor_id":"ACTOR-001","entry_point_id":"EP-001","threat_id":"T-001","affected_asset_ids":["ASSET-001"],"preconditions":["..."],"steps":["attacker action","security-boundary failure"],"outcome":"...","evidence":[],"provenance_tags":["code-verified"]}],
  "out_of_scope_stories": [{"story_id":"OOS-001","scenario":"...","reason":"...","reconsider_when":["..."],"evidence":[],"provenance_tags":["deployment-unknown"]}],
  "severity_calibration": {
    "model": "contextual-four-level-v1",
    "context_notes": ["Final CVSS is derived only after finding adjudication."],
    "evidence": [],
    "levels": [
      {"severity":"CRITICAL","criteria":["..."],"examples":[{"scenario":"...","rationale":"...","threat_ids":["T-001"]}],"not_applicable_reason":null},
      {"severity":"HIGH","criteria":["..."],"examples":[],"not_applicable_reason":"..."},
      {"severity":"MEDIUM","criteria":["..."],"examples":[],"not_applicable_reason":"..."},
      {"severity":"LOW","criteria":["..."],"examples":[],"not_applicable_reason":"..."}
    ]
  },
  "deprioritized": [{"entry_point_id":"EP-001","threat_class":"repudiation","reason":"...","evidence":[]}],
  "history_clusters": [{"cluster_id":"HC-001","entry_point_ids":["EP-001"],"weakness_class":"...","asset_ids":["ASSET-001"],"evidence":[],"sibling_locations":[]}],
  "entry_point_coverage": [{"entry_point_id":"EP-001","status":"THREAT|DEPRIORITIZED|GAP","threat_ids":["T-001"],"reason":null,"evidence":[]}],
  "open_questions": [{"question_id":"Q-001","question":"...","blocking":true,"status":"open|resolved","evidence":[]}],
  "provenance": {"target":"...","commit":"...","inputs":[],"owner":null},
  "manifest_digest": "sha256"
}
```

Use outcome-oriented threats. Evidence may be empty only for STRIDE gap-fill
threats; provenance must still explain their derivation. Every threat must have
at least one attacker story, and every non-empty asset set must have a security
invariant. Keep deployment and operator assumptions first-class rather than
folding them into threat prose. `out_of_scope_stories` is mandatory even when it
is an empty array.

Severity calibration always contains exactly `CRITICAL`, `HIGH`, `MEDIUM`, and
`LOW`. Each level needs criteria and either a project-specific example or an
explicit `not_applicable_reason`. This calibration ranks threat-model work; it
does not replace the independently derived post-adjudication CVSS 3.1 result.

Seal with `seal-semantic-manifest.mjs`, which invokes the shared
`threat-model-contract.mjs`. A complete semantic audit cannot contain `GAP`
entry-point coverage or an open blocking question.

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
