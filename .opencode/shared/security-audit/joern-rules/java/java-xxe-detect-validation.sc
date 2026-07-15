// L3 assist: find secure feature/property configuration near XML factories and sinks.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sinks = cpg.call.methodFullName(
  ".*DocumentBuilder\\.parse.*|" +
  ".*SAXParser\\.parse.*|" +
  ".*XMLReader\\.parse.*|" +
  ".*XMLInputFactory\\.createXMLStreamReader.*|" +
  ".*XMLInputFactory\\.createXMLEventReader.*|" +
  ".*Unmarshaller\\.unmarshal.*|" +
  ".*Transformer\\.transform.*|" +
  ".*SAXReader\\.read.*|" +
  ".*SAXBuilder\\.build.*"
).l

sinks.foreach { s =>
  val m = s.method
  val hasSetFeature = m.call.name("setFeature").nonEmpty
  val hasSetProperty = m.call.name("setProperty").nonEmpty
  val hasSetAttribute = m.call.name("setAttribute").nonEmpty
  val hasDisallowDoctype = m.code.contains("disallow-doctype-decl")
  val hasExternalGeneral = m.code.contains("external-general-entities")
  val hasExternalParameter = m.code.contains("external-parameter-entities")
  val hasSecureProcessing = m.code.contains("FEATURE_SECURE_PROCESSING") ||
    m.code.contains("secure-processing")
  val hasAccessExternal = m.code.contains("ACCESS_EXTERNAL")
  val hasStaxExternal = m.code.contains("IS_SUPPORTING_EXTERNAL_ENTITIES") ||
    m.code.contains("isSupportingExternalEntities")
  val hasSupportDtd = m.code.contains("SUPPORT_DTD") || m.code.contains("supportDTD")
  val hasEntityResolver = m.call.name("setEntityResolver").nonEmpty
  val hasXInclude = m.call.name("setXIncludeAware").nonEmpty ||
    m.code.contains("setXIncludeAware")

  println(
    s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
    s"line=${s.lineNumber.getOrElse(-1)}\t" +
    s"method=${m.fullName}\t" +
    s"has_setFeature=$hasSetFeature\t" +
    s"has_setProperty=$hasSetProperty\t" +
    s"has_setAttribute=$hasSetAttribute\t" +
    s"has_disallow_doctype=$hasDisallowDoctype\t" +
    s"has_external_general=$hasExternalGeneral\t" +
    s"has_external_parameter=$hasExternalParameter\t" +
    s"has_secure_processing=$hasSecureProcessing\t" +
    s"has_access_external=$hasAccessExternal\t" +
    s"has_stax_external_flag=$hasStaxExternal\t" +
    s"has_support_dtd=$hasSupportDtd\t" +
    s"has_entity_resolver=$hasEntityResolver\t" +
    s"has_xinclude_config=$hasXInclude\t" +
    s"sink=${s.methodFullName}"
  )
}
