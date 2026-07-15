// L3 assist: find nearby destination validation patterns around SSRF sinks.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinks = cpg.call.methodFullName(
    ".*URL\\.openConnection.*|" +
    ".*URL\\.openStream.*|" +
    ".*RestTemplate\\.(exchange|getForObject|getForEntity|postForObject|execute).*|" +
    ".*WebClient\\..*uri.*|" +
    ".*HttpClient\\.execute.*|" +
    ".*CloseableHttpClient\\.execute.*|" +
    ".*Request\\.Builder\\.url.*|" +
    ".*HttpRequest\\.Builder\\.uri.*"
  ).l

  sinks.foreach { s =>
    val m = s.method
    val hasStartsWith = m.call.name("startsWith|regionMatches").nonEmpty
    val hasAllowlist = m.call.name("contains|equals|equalsIgnoreCase|valueOf|fromValue").nonEmpty
    val hasParse = m.call.name("getHost|getScheme|getProtocol|toURI|create|parse").nonEmpty ||
      m.code.contains("URI.create") || m.code.contains("new URL")
    val hasDnsResolve = m.call.name("getAllByName|getByName|getAddress|getHostAddress").nonEmpty
    val hasRedirectControl = m.code.contains("setInstanceFollowRedirects") ||
      m.code.contains("followRedirects") || m.code.contains("RedirectStrategy")
    val hasConcat = m.call.name("concat|format|append").nonEmpty || m.code.contains("+")

    println(
      s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
      s"line=${s.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"has_startswith=$hasStartsWith\t" +
      s"has_allowlist_like=$hasAllowlist\t" +
      s"has_url_parse=$hasParse\t" +
      s"has_dns_resolve=$hasDnsResolve\t" +
      s"has_redirect_control=$hasRedirectControl\t" +
      s"has_concat_hint=$hasConcat\t" +
      s"sink=${s.methodFullName}"
    )
  }
}
