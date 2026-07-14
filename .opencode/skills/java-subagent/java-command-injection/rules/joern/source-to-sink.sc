// L2: source-to-sink dataflow for OS command injection candidates.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sourceCalls = cpg.call.methodFullName(
    ".*HttpServletRequest\\.getParameter.*|" +
    ".*HttpServletRequest\\.getHeader.*"
  ).argument

  val annotatedSources = cpg.parameter
    .where(_.annotation.name("RequestParam|PathVariable|RequestHeader|RequestBody"))

  val sinks = cpg.call.methodFullName(
    ".*Runtime\\.exec.*|" +
    ".*ProcessBuilder\\.<init>.*|" +
    ".*ProcessBuilder\\.command.*|" +
    ".*DefaultExecutor\\.execute.*|" +
    ".*CommandLine\\.parse.*|" +
    ".*CommandLine\\.addArguments.*"
  ).argument

  val flowsFromCalls = sinks.reachableByFlows(sourceCalls).l
  val flowsFromParams = sinks.reachableByFlows(annotatedSources).l
  val flows = flowsFromCalls ++ flowsFromParams

  flows.zipWithIndex.foreach { case (flow, idx) =>
    println(s"dataflow_id=CMDI-FLOW-$idx")
    flow.elements.foreach { e =>
      println(
        s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
        s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
      )
    }
  }

  println(s"total_flows=${flows.size}")
}
