// L3 assist: find nearby encoding / parameterization patterns around LDAP sinks.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinks = cpg.call.methodFullName(
    ".*DirContext\\.search.*|" +
    ".*InitialDirContext\\.search.*|" +
    ".*LdapTemplate\\.(search|authenticate|lookup|find).*|" +
    ".*HardcodedFilter\\..*|" +
    ".*Context\\.lookup.*"
  ).l

  sinks.foreach { s =>
    val m = s.method
    val hasEncoder = m.call.name("filterEncode|encodeFilterValue|nameEncode|encodeDnValue|escape").nonEmpty ||
      m.code.contains("LdapEncoder")
    val hasEqualsFilter = m.call.name("EqualsFilter|LikeFilter|AndFilter|OrFilter").nonEmpty ||
      m.code.contains("EqualsFilter") || m.code.contains("LdapQueryBuilder")
    val hasAllowlist = m.call.name("contains|equals|valueOf|fromValue|matches").nonEmpty
    val hasReplace = m.call.name("replace|replaceAll").nonEmpty
    val hasConcat = m.call.name("concat|format|append").nonEmpty || m.code.contains("+")
    val hasFilterArgs = m.code.contains("filterArgs") || s.argument.size >= 4

    println(
      s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
      s"line=${s.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"has_ldap_encoder=$hasEncoder\t" +
      s"has_filter_api=$hasEqualsFilter\t" +
      s"has_allowlist_like=$hasAllowlist\t" +
      s"has_escape_replace=$hasReplace\t" +
      s"has_concat_hint=$hasConcat\t" +
      s"has_filter_args_hint=$hasFilterArgs\t" +
      s"sink=${s.methodFullName}"
    )
  }
}
