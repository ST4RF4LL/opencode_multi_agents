# Web (JavaScript/Node.js) Static-Analysis Rule Gap

**Status**: GAP-REGISTERED — no Joern/CPG rule is created here. The existing
`joern-rules/java/` set targets JVM bytecode and does not fit browser
JavaScript or `node:http` server code. Rules below are **not yet validated**;
each records a confirmed TRUE_POSITIVE pattern from `audit-20260812-rvi09`
(three-party review, 67/67 TRUE_POSITIVE) as the future rule contract.

## Sink rules needed (grep-able first-pass patterns)

| Gap rule id (proposed) | Confirmed pattern | Source/sink model | Evidence (finding ids) |
|---|---|---|---|
| `web-token-verify-signature-split` | token parsed as `payload.split('.')[0]`; signature segment never compared; `exp` never enforced | HTTP `Authorization` header → `requireUser` trust decision | FA-INGRESS-AUTHN-CTRL-01, SNK-01, SNK-02, CTRL-07 |
| `web-writefilesync-traversal` | `path.join(base, body.filename)` + `mkdirSync(recursive)` + `writeFileSync` without normalize+confine | JSON body filename/content → `fs.writeFileSync` | FA-FILE-WRITE-SNK-01..04, CTRL-01, FW-FILE-WRITE-CFG-01 |
| `web-innerhtml-unsafe-sink` | `el.innerHTML = \`...${serverField}...\`` with no escape helper; token in `localStorage`; no CSP | served JSON / poisoned bundle → `innerHTML` sink → token read | FA-BROWSER-DOM-SNK-01, SNK-02, CTRL-01, CFG-01/02 |
| `web-body-accumulation-unbounded` | `data += chunk` with no byte cap, `JSON.parse(data)` unbounded, no content-length pre-check | raw request stream → memory exhaustion | FA-PLATFORM-DEPLOY-SNK-01, CFG-01, CTRL-02, FW-FILE-WRITE-CFG-02 |
| `web-async-handler-unhandled-rejection` | async request handler with throwing sync fs I/O, no try/catch, no `unhandledRejection` listener | crafted filename → EISDIR throw → process crash (Node >=15) | FA-PLATFORM-DEPLOY-SNK-03, CTRL-03, CFG-03, PCTRL-07 |
| `web-idor-path-id-no-ownership` | `pathname.split('/').pop()` → lookup by id → `res.json(rawRecord)` with no session compare / projection | URL path id → raw-record response | FA-INGRESS-AUTHZ-SNK-01/02/05, CTRL-02/03, CFG-02/03 |

## Control/config absence checks needed

- `web-set-cookie-missing-flags`: `Set-Cookie` without HttpOnly/Secure (FA-INGRESS-AUTHN-CTRL-02, SNK-03).
- `web-security-headers-absent`: response writers set only `Content-Type`; no CSP/XFO/nosniff/HSTS (FA-PLATFORM-DEPLOY-PCTRL-02, PSNK-02).
- `web-logging-absent`: single startup `console.log`, no audit events (FA-PLATFORM-DEPLOY-SNK-02, CFG-02, PCFG-04, PCTRL-06, PSNK-03).
- `web-plaintext-listener`: `listen(port)` without host binding/TLS, `node:https` never imported (FA-INGRESS-AUTHN-CTRL-08, FA-PLATFORM-DEPLOY-CTRL-01, PCFG-02, PSNK-01).

## Validation policy

Promote any of these to a first-class `<rule-id>.sc` + `.md` pair under
`joern-rules/web/` only after it runs against a real JavaScript CPG
(`joern-parse --language js`) with recorded TP/FP counts on the frozen
`redai/examples/webapp` target plus a clean negative sample. Until then they
remain gaps; do not ship unvalidated rules.

## Tagging

- Dimension/lens per proposed rule: see the corresponding
  `vulnerability-cases/web/<case-id>/case-summary.json` entries
  (threat_id T-01/T-03/T-04/T-05/T-08, focus areas
  FA-INGRESS-AUTHN / FA-INGRESS-AUTHZ / FA-FILE-WRITE / FA-BROWSER-DOM /
  FA-PLATFORM-DEPLOY, discovery_track=coverage).
