// L2: source-to-sink dataflow for open-redirect candidates.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sourceCalls = cpg.call.methodFullName(
    ".*HttpServletRequest\\.getParameter.*|" +
    ".*HttpServletRequest\\.getHeader.*"
  ).argument

  val annotatedSources = cpg.parameter
    .where(_.annotation.name("RequestParam|PathVariable|RequestHeader|RequestBody"))

  val sinks = cpg.call.methodFullName(
    ".*HttpServletResponse\\.sendRedirect.*|" +
    ".*HttpServletResponse\\.setHeader.*|" +
    ".*HttpServletResponse\\.addHeader.*|" +
    ".*RedirectView\\.<init>.*|" +
    ".*RedirectView\\.setUrl.*|" +
    ".*HttpHeaders\\.setLocation.*|" +
    ".*ModelAndView\\.setViewName.*|" +
    ".*ModelAndView\\.<init>.*"
  ).argument

  val allSinks = sinks

  val flowsFromCalls = allSinks.reachableByFlows(sourceCalls).l
  val flowsFromParams = allSinks.reachableByFlows(annotatedSources).l
  val flows = flowsFromCalls ++ flowsFromParams

  flows.zipWithIndex.foreach { case (flow, idx) =>
    println(s"dataflow_id=OPENREDIRECT-FLOW-$idx")
    flow.elements.foreach { e =>
      println(
        s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
        s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
      )
    }
  }

  println(s"total_flows=${flows.size}")
}
