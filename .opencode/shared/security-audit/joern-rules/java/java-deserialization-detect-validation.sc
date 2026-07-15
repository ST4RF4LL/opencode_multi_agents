// L3 assist: find nearby type-filter / safe-mode patterns around deserial sinks.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sinks = cpg.call.methodFullName(
  ".*ObjectInputStream\\.readObject.*|" +
  ".*ObjectInputStream\\.readUnshared.*|" +
  ".*XMLDecoder\\.readObject.*|" +
  ".*JSON\\.parse.*|" +
  ".*JSON\\.parseObject.*|" +
  ".*ObjectMapper\\.readValue.*|" +
  ".*Yaml\\.load.*|" +
  ".*XStream\\.fromXML.*|" +
  ".*Hessian2Input\\.readObject.*|" +
  ".*Kryo\\.readClassAndObject.*|" +
  ".*SerializationUtils\\.deserialize.*"
).l

sinks.foreach { s =>
  val m = s.method
  val code = m.code
  val hasObjectInputFilter =
    code.contains("ObjectInputFilter") ||
    code.contains("setObjectInputFilter") ||
    m.call.name("setObjectInputFilter|createFilter").nonEmpty
  val hasValidatingOIS =
    code.contains("ValidatingObjectInputStream") ||
    code.contains("accept(")
  val hasSafeConstructor =
    code.contains("SafeConstructor") ||
    code.contains("TagInspector")
  val hasXStreamSecurity =
    code.contains("setupDefaultSecurity") ||
    code.contains("allowTypes") ||
    code.contains("NoTypePermission")
  val hasFastjsonSafe =
    code.contains("safeMode") ||
    code.contains("setSafeMode") ||
    (code.contains("setAutoTypeSupport") && code.contains("false"))
  val hasJacksonTyping =
    code.contains("enableDefaultTyping") ||
    code.contains("activateDefaultTyping") ||
    code.contains("DefaultTyping")
  val hasAutoTypeOn =
    code.contains("setAutoTypeSupport(true)") ||
    code.contains("SupportAutoType")

  println(
    s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
    s"line=${s.lineNumber.getOrElse(-1)}\t" +
    s"method=${m.fullName}\t" +
    s"has_object_input_filter=$hasObjectInputFilter\t" +
    s"has_validating_ois=$hasValidatingOIS\t" +
    s"has_safe_constructor=$hasSafeConstructor\t" +
    s"has_xstream_security=$hasXStreamSecurity\t" +
    s"has_fastjson_safe=$hasFastjsonSafe\t" +
    s"has_jackson_typing=$hasJacksonTyping\t" +
    s"has_autotype_on=$hasAutoTypeOn\t" +
    s"sink=${s.methodFullName}"
  )
}
