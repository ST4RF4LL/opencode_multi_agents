// L1: locate OS command-related sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*Runtime\\.exec.*|" +
    ".*ProcessBuilder\\.<init>.*|" +
    ".*ProcessBuilder\\.command.*|" +
    ".*ProcessBuilder\\.start.*|" +
    ".*DefaultExecutor\\.execute.*|" +
    ".*Executor\\.execute.*|" +
    ".*CommandLine\\.parse.*|" +
    ".*CommandLine\\.<init>.*|" +
    ".*CommandLine\\.addArguments.*"

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
