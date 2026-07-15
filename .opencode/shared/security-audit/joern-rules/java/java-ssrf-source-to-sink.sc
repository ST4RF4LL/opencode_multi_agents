// L2: source-to-sink dataflow for SSRF candidates.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sourceCalls = cpg.call.methodFullName(
  ".*HttpServletRequest\\.getParameter.*|" +
  ".*HttpServletRequest\\.getHeader.*"
).argument

val annotatedSources = cpg.parameter
  .where(_.annotation.name("RequestParam|PathVariable|RequestHeader|RequestBody"))

val sinks = cpg.call.methodFullName(
  ".*URL\\.openConnection.*|" +
  ".*URL\\.openStream.*|" +
  ".*RestTemplate\\.(exchange|getForObject|getForEntity|postForObject|execute).*|" +
  ".*WebClient\\..*uri.*|" +
  ".*HttpClient\\.execute.*|" +
  ".*CloseableHttpClient\\.execute.*|" +
  ".*Request\\.Builder\\.url.*|" +
  ".*HttpRequest\\.Builder\\.uri.*"
).argument

val urlCtors = cpg.call.methodFullName(".*URL\\.<init>.*|.*URI\\.create.*").argument

val allSinks = sinks ++ urlCtors

val flowsFromCalls = allSinks.reachableByFlows(sourceCalls).l
val flowsFromParams = allSinks.reachableByFlows(annotatedSources).l
val flows = flowsFromCalls ++ flowsFromParams

flows.zipWithIndex.foreach { case (flow, idx) =>
  println(s"dataflow_id=SSRF-FLOW-$idx")
  flow.elements.foreach { e =>
    println(
      s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
      s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
    )
  }
}

println(s"total_flows=${flows.size}")
