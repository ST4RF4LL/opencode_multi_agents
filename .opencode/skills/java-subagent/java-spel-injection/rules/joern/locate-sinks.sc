// L1: locate SpEL-related sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*ExpressionParser\\.parseExpression.*|" +
    ".*SpelExpressionParser\\.parseExpression.*|" +
    ".*Expression\\.getValue.*|" +
    ".*Expression\\.setValue.*|" +
    ".*SpelExpression\\.getValue.*|" +
    ".*SpelExpression\\.setValue.*"

  val sinks = cpg.call.methodFullName(sinkPattern).l

  sinks.foreach { c =>
    println(
      s"sink_candidate\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
      s"line=${c.lineNumber.getOrElse(-1)}\t" +
      s"method=${c.method.fullName}\t" +
      s"sink=${c.methodFullName}\t" +
      s"code=${c.code}"
    )
  }

  val contextHints = cpg.call.methodFullName(
    ".*StandardEvaluationContext\\.<init>.*|" +
    ".*StandardEvaluationContext\\.setRootObject.*|" +
    ".*StandardEvaluationContext\\.setVariable.*|" +
    ".*TemplateParserContext\\.<init>.*"
  ).l

  contextHints.foreach { c =>
    println(
      s"context_hint\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
      s"line=${c.lineNumber.getOrElse(-1)}\t" +
      s"method=${c.method.fullName}\t" +
      s"api=${c.methodFullName}\t" +
      s"code=${c.code}"
    )
  }

  println(s"total_sink_candidates=${sinks.size}")
  println(s"total_context_hints=${contextHints.size}")
}
