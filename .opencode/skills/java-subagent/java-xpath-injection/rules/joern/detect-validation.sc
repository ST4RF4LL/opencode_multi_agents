// L3 assist: find nearby validation / parameterization patterns around XPath sinks.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinks = cpg.call.methodFullName(
    ".*XPath\\.compile.*|" +
    ".*XPath\\.evaluate.*|" +
    ".*XPathExpression\\.evaluate.*|" +
    ".*XPathCompiler\\.compile.*|" +
    ".*XPathEvaluator\\.(compile|evaluate).*"
  ).l

  sinks.foreach { s =>
    val m = s.method
    val hasVariableResolver =
      m.call.name("setXPathVariableResolver|resolveVariable|setVariable|declareVariable").nonEmpty
    val hasDollarVar = m.code.contains("$")
    val hasAllowlist = m.call.name("contains|equals|valueOf|fromValue").nonEmpty
    val hasReplace = m.call.name("replace|replaceAll|escapeXml").nonEmpty
    val hasConcat = m.call.name("concat|format|append").nonEmpty || m.code.contains("+")

    println(
      s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
      s"line=${s.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"has_variable_resolver=$hasVariableResolver\t" +
      s"has_dollar_var_hint=$hasDollarVar\t" +
      s"has_allowlist_like=$hasAllowlist\t" +
      s"has_escape_replace=$hasReplace\t" +
      s"has_concat_hint=$hasConcat\t" +
      s"sink=${s.methodFullName}"
    )
  }
}
