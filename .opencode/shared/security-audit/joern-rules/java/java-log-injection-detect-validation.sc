// L3 assist: find nearby sanitization / parameterization patterns around log sinks.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sinks = cpg.call.methodFullName(
  ".*Logger\\.(trace|debug|info|warn|error|fatal|log).*|" +
  ".*Log\\.(trace|debug|info|warn|error|fatal).*|" +
  ".*MDC\\.put.*|" +
  ".*ThreadContext\\.(put|push).*"
).l

sinks.foreach { s =>
  val m = s.method
  val hasReplaceNl = m.call.name("replace|replaceAll|strip|translate").nonEmpty ||
    m.code.matches("(?s).*\\\\[nNrR].*")
  val hasLengthLimit = m.call.name("substring|length|min|max").nonEmpty
  val hasConcat = m.call.name("concat|format|append").nonEmpty || m.code.contains("+")
  val hasPlaceholder = m.code.contains("{}") || m.code.contains("%s")
  val hasEncode = m.call.name("escape|encode|htmlEscape|encodeForHTML").nonEmpty

  println(
    s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
    s"line=${s.lineNumber.getOrElse(-1)}\t" +
    s"method=${m.fullName}\t" +
    s"has_newline_sanitize_hint=$hasReplaceNl\t" +
    s"has_length_limit_hint=$hasLengthLimit\t" +
    s"has_concat_hint=$hasConcat\t" +
    s"has_placeholder_hint=$hasPlaceholder\t" +
    s"has_encode_hint=$hasEncode\t" +
    s"sink=${s.methodFullName}"
  )
}
