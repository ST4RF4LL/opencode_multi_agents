// L3 assist: find nearby validation / parameterization patterns around SQL sinks.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinks = cpg.call.methodFullName(
    ".*Statement\\.execute.*|" +
    ".*prepareStatement.*|" +
    ".*JdbcTemplate\\.(query|update|execute).*|" +
    ".*createNativeQuery.*|" +
    ".*createQuery.*"
  ).l

  sinks.foreach { s =>
    val m = s.method
    val hasSetParam = m.call.name("setString|setInt|setLong|setObject|setParameter|setParams").nonEmpty
    val hasAllowlist = m.call.name("contains|equals|valueOf|fromValue").nonEmpty
    val hasReplace = m.call.name("replace|replaceAll|escapeSql").nonEmpty
    val hasConcat = m.call.name("concat|format|append").nonEmpty || m.code.contains("+")

    println(
      s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
      s"line=${s.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"has_param_binding=$hasSetParam\t" +
      s"has_allowlist_like=$hasAllowlist\t" +
      s"has_escape_replace=$hasReplace\t" +
      s"has_concat_hint=$hasConcat\t" +
      s"sink=${s.methodFullName}"
    )
  }
}
