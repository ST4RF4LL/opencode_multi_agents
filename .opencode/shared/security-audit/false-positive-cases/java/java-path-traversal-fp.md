# False-Positive Patterns: java-path-traversal

- **language**: java
- **skill**: `java-path-traversal`
- **weakness**: `path-traversal`
- **dimension**: D5
- **source**: vuln_skill_builder `analysis/false-positive-patterns.yaml`

## Not a vulnerability

### `constant-path-io`
- Pattern: File/NIO I/O with fully constant path and no external influence
- Reason: no attacker-controlled path component

### `fixed-id-to-path-map`
- Pattern: user selects among predefined file ids mapped to constant paths under baseDir
- Reason: attacker cannot introduce path segments

### `normalize-and-startswith-basedir`
- Pattern: resolve + normalize + startsWith(baseDir absolute) with fail-closed reject
- Reason: effective base-directory confinement

### `server-generated-upload-name`
- Pattern: multipart stored with UUID/random name under fixed upload root; original name only metadata
- Reason: client filename does not enter filesystem path

### `zip-entry-confined`
- Pattern: Zip extract with normalize + startsWith(destDir) before write
- Reason: Zip Slip mitigated

### `test-only-file-io`
- Pattern: path helpers only referenced from test sources
- Reason: not production reachable

### `basename-allowlist-storage`
- Pattern: only allowlisted basenames under fixed dir; separators rejected
- Reason: no directory traversal surface

## Needs deeper review

### `filenameutils-getname-alone`
- Pattern: FilenameUtils.getName(user) then new File(base, name)
- Reason: PARTIAL only; absolute/edge cases and missing normalize+startsWith still matter; do not treat as strong

### `blacklist-dotdot`
- Pattern: if (path.contains("..")) reject
- Reason: weak; encoding and alternate separators may bypass

### `startsWith-without-normalize`
- Pattern: path.startsWith(base) without normalize
- Reason: incomplete confinement depending on check order

### `normalize-without-startswith`
- Pattern: path.normalize() then open without base check
- Reason: absolute or multi-segment escape still possible

### `download-by-filename-param`
- Pattern: getParameter("filename") -> FileInputStream(base + name)
- Reason: classic classic-dotdot / download-path-param

### `zip-slip-extract-loop`
- Pattern: while ((e = zis.getNextEntry()) != null) write to dest/e.getName()
- Reason: Zip Slip subtype

### `multipart-original-as-path`
- Pattern: getOriginalFilename used in storage path
- Reason: multipart-filename subtype

### `wrapper-util`
- Pattern: custom FileUtil/StorageService read(String)
- Reason: sink is indirection; expand to real File/NIO I/O
