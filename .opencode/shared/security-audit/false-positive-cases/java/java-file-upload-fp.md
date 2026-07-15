# False-Positive Patterns: java-file-upload

- **language**: java
- **skill**: `java-file-upload`
- **weakness**: `file-upload`
- **dimension**: D5
- **source**: vuln_skill_builder `analysis/false-positive-patterns.yaml`

## Not a vulnerability

### `strong-extension-allowlist-private-store`
- Pattern: fail-closed extension allowlist + server-generated name + non-webroot storage
- Reason: effective upload type policy and safe storage

### `image-reencode-pipeline`
- Pattern: decode image and reencode to fixed format discarding original bytes
- Reason: original dangerous content not preserved

### `private-bucket-signed-url`
- Pattern: private object storage with allowlist and no public ACL
- Reason: no unrestricted public executable storage

### `test-only-upload`
- Pattern: upload helpers only in test sources
- Reason: not production reachable

### `constant-fixture-copy`
- Pattern: copy of classpath fixture with constant name
- Reason: no attacker-controlled upload

### `pure-path-only-escape`
- Pattern: type policy sound but filename has ../
- Reason: handoff to java-path-traversal; not primary CWE-434 finding here

## Needs deeper review

### `content-type-only`
- Pattern: if (getContentType().startsWith("image/")) store as-is
- Reason: mime-only-validation subtype

### `no-extension-check`
- Pattern: transferTo / Files.copy with original filename, no type check
- Reason: unrestricted-extension subtype

### `webroot-upload-dir`
- Pattern: store under getRealPath or src/main/webapp or static/
- Reason: executable-in-webroot subtype

### `double-extension`
- Pattern: endsWith(".jpg") but accepts name.jpg.jsp or similar
- Reason: double-extension-bypass

### `svg-allowed-as-image`
- Pattern: allow .svg or image/svg+xml and serve inline
- Reason: svg-html-stored-content

### `blacklist-jsp-only`
- Pattern: reject only .jsp
- Reason: weak; other handlers and bypasses remain

### `wrapper-upload-service`
- Pattern: UploadService.save(MultipartFile)
- Reason: expand to real store and policy
