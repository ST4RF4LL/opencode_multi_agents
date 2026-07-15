// L3 assist: find nearby sandbox / allowlist patterns around SpEL sinks.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sinks = cpg.call.methodFullName(
  ".*ExpressionParser\\.parseExpression.*|" +
  ".*SpelExpressionParser\\.parseExpression.*|" +
  ".*Expression\\.getValue.*|" +
  ".*Expression\\.setValue.*"
).l

sinks.foreach { s =>
  val m = s.method
  val hasSimpleCtx =
    m.call.name(".*SimpleEvaluationContext.*").nonEmpty ||
    m.code.contains("SimpleEvaluationContext")
  val hasStandardCtx =
    m.call.name(".*StandardEvaluationContext.*").nonEmpty ||
    m.code.contains("StandardEvaluationContext")
  val hasTemplateCtx =
    m.code.contains("TemplateParserContext") || m.code.contains("ParserContext")
  val hasAllowlist =
    m.call.name("contains|equals|valueOf|fromValue|isAllowed|allowedExpressions").nonEmpty
  val hasBlacklist =
    m.call.name("contains|replace|replaceAll|matches").nonEmpty &&
    (m.code.contains("T(") || m.code.contains("Runtime") || m.code.contains("getClass"))
  val hasConcat =
    m.call.name("concat|format|append").nonEmpty || m.code.contains("+")

  println(
    s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
    s"line=${s.lineNumber.getOrElse(-1)}\t" +
    s"method=${m.fullName}\t" +
    s"has_simple_evaluation_context=$hasSimpleCtx\t" +
    s"has_standard_evaluation_context=$hasStandardCtx\t" +
    s"has_template_parser_context=$hasTemplateCtx\t" +
    s"has_allowlist_like=$hasAllowlist\t" +
    s"has_blacklist_like=$hasBlacklist\t" +
    s"has_concat_hint=$hasConcat\t" +
    s"sink=${s.methodFullName}"
  )
}
