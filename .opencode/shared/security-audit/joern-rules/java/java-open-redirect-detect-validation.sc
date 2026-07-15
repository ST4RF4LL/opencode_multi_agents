// L3 assist: find nearby redirect destination validation patterns around sinks.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sinks = cpg.call.methodFullName(
  ".*HttpServletResponse\\.sendRedirect.*|" +
  ".*HttpServletResponse\\.setHeader.*|" +
  ".*HttpServletResponse\\.addHeader.*|" +
  ".*RedirectView\\.<init>.*|" +
  ".*RedirectView\\.setUrl.*|" +
  ".*HttpHeaders\\.setLocation.*"
).l

sinks.foreach { s =>
  val m = s.method
  val hasStartsWith = m.call.name("startsWith|regionMatches").nonEmpty
  val hasAllowlist = m.call.name("contains|equals|equalsIgnoreCase|valueOf|fromValue").nonEmpty
  val hasParse = m.call.name("getHost|getScheme|getProtocol|toURI|create|parse").nonEmpty ||
    m.code.contains("URI.create") || m.code.contains("new URL")
  val hasSlashCheck = m.code.contains("startsWith(\"/\")") || m.code.contains("startsWith(\"/\")")
  val hasRedirectPrefix = m.code.contains("redirect:")
  val hasConcat = m.call.name("concat|format|append").nonEmpty || m.code.contains("+")

  println(
    s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
    s"line=${s.lineNumber.getOrElse(-1)}\t" +
    s"method=${m.fullName}\t" +
    s"has_startswith=$hasStartsWith\t" +
    s"has_allowlist_like=$hasAllowlist\t" +
    s"has_url_parse=$hasParse\t" +
    s"has_slash_check=$hasSlashCheck\t" +
    s"has_redirect_prefix=$hasRedirectPrefix\t" +
    s"has_concat_hint=$hasConcat\t" +
    s"sink=${s.methodFullName}"
  )
}
