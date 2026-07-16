---
name: java-web-security-review
description: Review Java web applications for authentication, authorization, Spring Security, SSRF, file handling, and framework configuration issues.
license: MIT
metadata:
  role: java-source-auditor
  collection: java-subagent
---

# Java Web Security Review

Use this skill for Java/JVM HTTP services, API servers, admin panels, and framework configuration.

## Focus Areas

- Spring Security filters, interceptors, method security, route matchers, and annotation coverage.
- Object-level authorization, tenant isolation, admin-only operations, and insecure direct object access.
- SSRF, redirects, CORS/CSRF, session flags, debug endpoints, actuator exposure, and error handling.
- Uploads, downloads, archive extraction, path traversal, and temporary file handling.
- Maven/Gradle dependencies and production reachability of test or debug utilities.
- XSS / template unescape paths → progressive-load `java-xss`.
- Log forging / CRLF into logger messages → progressive-load `java-log-injection`.

## Evidence Requirements

Tie each issue to an entrypoint and exact framework configuration path. Verify that filters and annotations apply to the route under review.

## Progressive Deep Packs

| Signal | Load skill |
|--------|------------|
| SSRF / RestTemplate / WebClient / URL.openConnection | `java-ssrf` |
| Open redirect / sendRedirect / Location / redirect: | `java-open-redirect` |
| Path traversal / Zip Slip / getOriginalFilename | `java-path-traversal` |
| Unrestricted upload / MultipartFile | `java-file-upload` |
| IDOR / findById without ownership | `java-idor` |
| Mass assignment / @ModelAttribute entity | `java-mass-assignment` |
| CSRF / csrf().disable / cookie-session mutations | `java-csrf` |
| JWT decode without verify / alg=none | `java-jwt-misuse` |
| Hardcoded secrets in yml/properties/source | `java-hardcoded-secrets` |
| XSS / templates | `java-xss` |
| Log forging | `java-log-injection` |
