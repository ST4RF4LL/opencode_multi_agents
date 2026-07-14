// L2: source-to-sink dataflow for log injection candidates.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sourceCalls = cpg.call.methodFullName(
  ".*HttpServletRequest\\.getParameter.*|" +
  ".*HttpServletRequest\\.getHeader.*|" +
  ".*HttpServletRequest\\.getRemoteUser.*|" +
  ".*Principal\\.getName.*"
).argument

val annotatedSources = cpg.parameter
  .where(_.annotation.name("RequestParam|PathVariable|RequestHeader|RequestBody|CookieValue"))

val sinks = cpg.call.methodFullName(
  ".*org\\.slf4j\\.Logger\\.(trace|debug|info|warn|error).*|" +
  ".*org\\.apache\\.logging\\.log4j\\.Logger\\.(trace|debug|info|warn|error|fatal|log|printf).*|" +
  ".*java\\.util\\.logging\\.Logger\\.(log|severe|warning|info).*|" +
  ".*org\\.apache\\.commons\\.logging\\.Log\\.(trace|debug|info|warn|error|fatal).*|" +
  ".*org\\.slf4j\\.MDC\\.put.*|" +
  ".*org\\.apache\\.logging\\.log4j\\.ThreadContext\\.(put|push).*"
).argument

val flowsFromCalls = sinks.reachableByFlows(sourceCalls).l
val flowsFromParams = sinks.reachableByFlows(annotatedSources).l
val flows = flowsFromCalls ++ flowsFromParams

flows.zipWithIndex.foreach { case (flow, idx) =>
  println(s"dataflow_id=LOGINJ-FLOW-$idx")
  flow.elements.foreach { e =>
    println(
      s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
      s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
    )
  }
}

println(s"total_flows=${flows.size}")
