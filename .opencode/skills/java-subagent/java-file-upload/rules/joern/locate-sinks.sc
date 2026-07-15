// L1: locate file upload storage sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*MultipartFile\\.transferTo.*|" +
    ".*CommonsMultipartFile\\.transferTo.*|" +
    ".*Part\\.write.*|" +
    ".*FileItem\\.write.*|" +
    ".*DiskFileItem\\.write.*|" +
    ".*Files\\.copy.*|" +
    ".*Files\\.write.*|" +
    ".*Files\\.newOutputStream.*|" +
    ".*FileOutputStream\\.<init>.*|" +
    ".*FileWriter\\.<init>.*|" +
    ".*ServletContext\\.getRealPath.*|" +
    ".*java\\.io\\.File\\.<init>.*"

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
