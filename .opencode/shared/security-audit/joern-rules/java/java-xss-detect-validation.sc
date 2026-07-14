// L3 assist: find nearby encoding/sanitization patterns around XSS sinks.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sinks = cpg.call.methodFullName(
  ".*PrintWriter\\.print.*|" +
  ".*PrintWriter\\.println.*|" +
  ".*PrintWriter\\.write.*|" +
  ".*Model\\.addAttribute.*|" +
  ".*ModelAndView\\.addObject.*|" +
  ".*HttpServletResponse\\.sendError.*"
).l

sinks.foreach { s =>
  val m = s.method
  val hasOwaspEncode = m.call.name(
    "forHtml|forHtmlContent|forHtmlAttribute|forJavaScript|forJavaScriptBlock|forCssString|forUriComponent|forUri"
  ).nonEmpty || m.code.contains("Encode.")
  val hasHtmlEscape = m.call.name("htmlEscape|escapeHtml4|escapeXml|escapeXml11").nonEmpty
  val hasSanitizer = m.call.name("sanitize|HtmlPolicyBuilder|PolicyFactory").nonEmpty ||
    m.code.contains("HtmlPolicyBuilder") || m.code.contains("Sanitizers.")
  val hasBlacklist = m.call.name("replace|replaceAll|contains").nonEmpty &&
    (m.code.toLowerCase.contains("script") || m.code.contains("<"))
  val hasConcat = m.call.name("concat|format|append").nonEmpty || m.code.contains("+")

  println(
    s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
    s"line=${s.lineNumber.getOrElse(-1)}\t" +
    s"method=${m.fullName}\t" +
    s"has_owasp_encode=$hasOwaspEncode\t" +
    s"has_html_escape=$hasHtmlEscape\t" +
    s"has_sanitizer=$hasSanitizer\t" +
    s"has_blacklist_like=$hasBlacklist\t" +
    s"has_concat_hint=$hasConcat\t" +
    s"sink=${s.methodFullName}"
  )
}
