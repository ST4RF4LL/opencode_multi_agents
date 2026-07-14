// L1: locate XPath-related sinks. Output SinkCandidate, not findings.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sinkPattern =
  ".*XPath\\.compile.*|" +
  ".*XPath\\.evaluate.*|" +
  ".*XPathExpression\\.evaluate.*|" +
  ".*XPathCompiler\\.compile.*|" +
  ".*XPathEvaluator\\.compile.*|" +
  ".*XPathEvaluator\\.evaluate.*|" +
  ".*XPathEvaluator\\.createExpression.*"

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

println(s"total_sink_candidates=${sinks.size}")
