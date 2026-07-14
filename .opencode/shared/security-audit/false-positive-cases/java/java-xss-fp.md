# False-Positive Patterns: java-xss

- **language**: java
- **skill**: `java-xss`
- **weakness**: `xss`
- **dimension**: D1
- **source**: vuln_skill_builder `analysis/false-positive-patterns.yaml`

## Not a vulnerability

### `owasp-encode-matching-context`
- Pattern: Encode.forHtml/forJs/forCss/forUri used for matching output context and result reaches sink
- Reason: context-aware encoding prevents injection in that context

### `thymeleaf-th-text`
- Pattern: th:text with user data, no th:utext / unescaped inline
- Reason: default HTML escaping

### `jstl-cout-default`
- Pattern: c:out without escapeXml=false
- Reason: default XML/HTML escaping

### `freemarker-auto-esc`
- Pattern: .ftlh or HTML output format with auto_esc, no ?no_esc around user data
- Reason: engine escapes interpolations

### `json-rest-only`
- Pattern: @ResponseBody application/json with structured serialization, not embedded in HTML page
- Reason: classic HTML XSS not applicable without HTML consumption

## Needs deeper review

### `writer-print-param`
- Pattern: response.getWriter().print(request.getParameter(...))
- Reason: classic reflected XSS

### `model-to-utext`
- Pattern: model attribute from user input rendered with th:utext or raw EL
- Reason: unescaped template output

### `encode-forhtml-in-script`
- Pattern: HTML encoder used to build JS string or script block
- Reason: wrong encoding context

### `escapeXml-false`
- Pattern: c:out escapeXml=false or equivalent
- Reason: explicit disable of escaping

### `blacklist-script-replace`
- Pattern: replace/contains on script tags only
- Reason: weak sanitizer; still Candidate if dataflow exists

### `senderror-user-message`
- Pattern: sendError(code, userMessage)
- Reason: container error pages may reflect message as HTML

### `stored-comment-render`
- Pattern: DB field written to HTML without encoding
- Reason: stored XSS; confirm original input path

### `custom-html-helper`
- Pattern: HtmlUtil/ViewHelper render(String)
- Reason: sink indirection; expand to real writer/template

