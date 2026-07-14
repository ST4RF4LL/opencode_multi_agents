// L1: locate logging sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*org\\.slf4j\\.Logger\\.(trace|debug|info|warn|error).*|" +
    ".*org\\.apache\\.logging\\.log4j\\.Logger\\.(trace|debug|info|warn|error|fatal|log|printf).*|" +
    ".*java\\.util\\.logging\\.Logger\\.(log|severe|warning|info|fine|finer|finest).*|" +
    ".*org\\.apache\\.commons\\.logging\\.Log\\.(trace|debug|info|warn|error|fatal).*|" +
    ".*org\\.slf4j\\.MDC\\.put.*|" +
    ".*org\\.apache\\.logging\\.log4j\\.ThreadContext\\.(put|push).*"

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
