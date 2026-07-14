// L1: locate LDAP-related sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*DirContext\\.search.*|" +
    ".*InitialDirContext\\.search.*|" +
    ".*Context\\.lookup.*|" +
    ".*Context\\.bind.*|" +
    ".*Context\\.rebind.*|" +
    ".*LdapTemplate\\.search.*|" +
    ".*LdapTemplate\\.searchForObject.*|" +
    ".*LdapTemplate\\.authenticate.*|" +
    ".*LdapTemplate\\.lookup.*|" +
    ".*LdapTemplate\\.find.*|" +
    ".*LdapTemplate\\.findOne.*|" +
    ".*HardcodedFilter\\..*|" +
    ".*LDAPConnection\\.search.*"

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

  println(s"total_sink_candidates=${sinks.size}")
}
