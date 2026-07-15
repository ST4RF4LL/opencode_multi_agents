// L2: source-to-sink dataflow for SpEL injection candidates.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sourceCalls = cpg.call.methodFullName(
    ".*HttpServletRequest\\.getParameter.*|" +
    ".*HttpServletRequest\\.getHeader.*"
  ).argument

  val annotatedSources = cpg.parameter
    .where(_.annotation.name("RequestParam|PathVariable|RequestHeader|RequestBody|CookieValue"))

  val parseSinks = cpg.call.methodFullName(
    ".*ExpressionParser\\.parseExpression.*|" +
    ".*SpelExpressionParser\\.parseExpression.*"
  ).argument(1)

  val evalSinks = cpg.call.methodFullName(
    ".*Expression\\.getValue.*|" +
    ".*Expression\\.setValue.*|" +
    ".*SpelExpression\\.getValue.*|" +
    ".*SpelExpression\\.setValue.*"
  )

  val flowsParseFromCalls = parseSinks.reachableByFlows(sourceCalls).l
  val flowsParseFromParams = parseSinks.reachableByFlows(annotatedSources).l
  val flowsEvalFromCalls = evalSinks.argument.reachableByFlows(sourceCalls).l
  val flowsEvalFromParams = evalSinks.argument.reachableByFlows(annotatedSources).l
  val flows =
    flowsParseFromCalls ++ flowsParseFromParams ++ flowsEvalFromCalls ++ flowsEvalFromParams

  flows.zipWithIndex.foreach { case (flow, idx) =>
    println(s"dataflow_id=SPEL-FLOW-$idx")
    flow.elements.foreach { e =>
      println(
        s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
        s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
      )
    }
  }

  println(s"total_flows=${flows.size}")
}
