// L1: locate SQL-related sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*Statement\\.execute.*|" +
    ".*Statement\\.executeQuery.*|" +
    ".*Statement\\.executeUpdate.*|" +
    ".*Connection\\.prepareStatement.*|" +
    ".*JdbcTemplate\\.query.*|" +
    ".*JdbcTemplate\\.update.*|" +
    ".*JdbcTemplate\\.execute.*|" +
    ".*NamedParameterJdbcTemplate\\..*|" +
    ".*EntityManager\\.createNativeQuery.*|" +
    ".*EntityManager\\.createQuery.*|" +
    ".*Session\\.createSQLQuery.*|" +
    ".*Session\\.createNativeQuery.*|" +
    ".*Session\\.createQuery.*"

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
