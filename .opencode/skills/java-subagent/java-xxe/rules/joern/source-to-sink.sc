// L2: source-to-sink dataflow for XXE candidates.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sourceCalls = cpg.call.methodFullName(
    ".*HttpServletRequest\\.getInputStream.*|" +
    ".*HttpServletRequest\\.getReader.*|" +
    ".*HttpServletRequest\\.getParameter.*|" +
    ".*HttpServletRequest\\.getPart.*|" +
    ".*Part\\.getInputStream.*|" +
    ".*MultipartFile\\.getInputStream.*|" +
    ".*MultipartFile\\.getBytes.*|" +
    ".*URL\\.openStream.*"
  ).argument

  val annotatedSources = cpg.parameter
    .where(_.annotation.name("RequestBody|RequestPart|RequestParam|PathVariable"))

  val sinks = cpg.call.methodFullName(
    ".*DocumentBuilder\\.parse.*|" +
    ".*SAXParser\\.parse.*|" +
    ".*XMLReader\\.parse.*|" +
    ".*XMLInputFactory\\.createXMLStreamReader.*|" +
    ".*XMLInputFactory\\.createXMLEventReader.*|" +
    ".*Unmarshaller\\.unmarshal.*|" +
    ".*Transformer\\.transform.*|" +
    ".*SAXReader\\.read.*|" +
    ".*SAXBuilder\\.build.*|" +
    ".*DocumentHelper\\.parseText.*"
  ).argument(1)

  val flowsFromCalls = sinks.reachableByFlows(sourceCalls).l
  val flowsFromParams = sinks.reachableByFlows(annotatedSources).l
  val flows = flowsFromCalls ++ flowsFromParams

  flows.zipWithIndex.foreach { case (flow, idx) =>
    println(s"dataflow_id=XXE-FLOW-$idx")
    flow.elements.foreach { e =>
      println(
        s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
        s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
      )
    }
  }

  println(s"total_flows=${flows.size}")
}
