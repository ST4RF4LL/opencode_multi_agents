// L1: locate XML parse/unmarshal sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*DocumentBuilder\\.parse.*|" +
    ".*SAXParser\\.parse.*|" +
    ".*XMLReader\\.parse.*|" +
    ".*XMLInputFactory\\.createXMLStreamReader.*|" +
    ".*XMLInputFactory\\.createXMLEventReader.*|" +
    ".*Unmarshaller\\.unmarshal.*|" +
    ".*TransformerFactory\\.newTransformer.*|" +
    ".*TransformerFactory\\.newTemplates.*|" +
    ".*Transformer\\.transform.*|" +
    ".*SchemaFactory\\.newSchema.*|" +
    ".*SAXReader\\.read.*|" +
    ".*DocumentHelper\\.parseText.*|" +
    ".*SAXBuilder\\.build.*|" +
    ".*XMLDecoder\\.readObject.*"

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

  val factories = cpg.call.methodFullName(
    ".*DocumentBuilderFactory\\.newInstance.*|" +
    ".*SAXParserFactory\\.newInstance.*|" +
    ".*XMLInputFactory\\.newInstance.*|" +
    ".*XMLInputFactory\\.newFactory.*|" +
    ".*TransformerFactory\\.newInstance.*|" +
    ".*SchemaFactory\\.newInstance.*"
  ).l

  factories.foreach { c =>
    println(
      s"factory_candidate\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
      s"line=${c.lineNumber.getOrElse(-1)}\t" +
      s"method=${c.method.fullName}\t" +
      s"factory=${c.methodFullName}\t" +
      s"code=${c.code}"
    )
  }

  println(s"total_sink_candidates=${sinks.size}")
  println(s"total_factory_candidates=${factories.size}")
}
