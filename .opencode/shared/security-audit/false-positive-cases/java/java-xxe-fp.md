# False-Positive Patterns: java-xxe

- **language**: java
- **skill**: `java-xxe`
- **weakness**: `xxe`
- **dimension**: D1
- **source**: vuln_skill_builder `analysis/false-positive-patterns.yaml`

## Not a vulnerability

### `strong-dom-hardening`
- Pattern: DocumentBuilderFactory with disallow-doctype-decl + external entities false + ACCESS_EXTERNAL_* empty before parse
- Reason: effective secure configuration on same factory instance

### `strong-stax-hardening`
- Pattern: XMLInputFactory IS_SUPPORTING_EXTERNAL_ENTITIES=false and SUPPORT_DTD=false before create*Reader
- Reason: StAX external entity resolution disabled

### `strong-transformer-hardening`
- Pattern: TransformerFactory FEATURE_SECURE_PROCESSING + ACCESS_EXTERNAL_DTD/STYLESHEET empty
- Reason: external access disabled for XSLT/XML transform

### `trusted-classpath-xml-only`
- Pattern: parse of constant classpath/resource XML with no external input influence
- Reason: no untrusted document content

### `test-only-parser`
- Pattern: XML parse helper only referenced from test sources
- Reason: not production reachable

### `xpathi-only-misclass`
- Pattern: XPath.compile/evaluate string concat without insecure XML parser config
- Reason: separate vulnerability class (CWE-643); owned by java-xpath-injection

### `pure-ssrf-misclass`
- Pattern: HTTP client to user URL without XML parse/entity resolution
- Reason: separate vulnerability class; owned by java-ssrf

## Needs deeper review

### `default-document-builder`
- Pattern: DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(untrusted)
- Reason: classic insecure default; high priority candidate

### `stax-missing-flags`
- Pattern: XMLInputFactory.newFactory() without IS_SUPPORTING_EXTERNAL_ENTITIES false
- Reason: common StAX XXE pattern

### `feature-secure-processing-only`
- Pattern: only FEATURE_SECURE_PROCESSING set
- Reason: often incomplete; verify JDK version and remaining vectors

### `flags-on-wrong-instance`
- Pattern: secure features set but parser obtained from different factory
- Reason: invalid control

### `jaxb-raw-stream`
- Pattern: Unmarshaller.unmarshal(InputStream) without hardened reader
- Reason: depends on underlying parser defaults

### `wrapper-xml-util`
- Pattern: XmlUtil.parse / XmlHelper.toDocument
- Reason: expand to real factory configuration and sink

### `url-fetch-then-parse`
- Pattern: fetch remote body then parse as XML
- Reason: may combine SSRF and XXE; classify primary vector carefully

### `partial-entity-disable`
- Pattern: only external-general-entities false
- Reason: parameter entity / alternate vector may remain
