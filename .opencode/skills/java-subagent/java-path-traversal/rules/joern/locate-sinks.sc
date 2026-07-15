// L1: locate file path / Zip extract sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*FileInputStream\\.<init>.*|" +
    ".*FileOutputStream\\.<init>.*|" +
    ".*FileReader\\.<init>.*|" +
    ".*FileWriter\\.<init>.*|" +
    ".*RandomAccessFile\\.<init>.*|" +
    ".*java\\.io\\.File\\.<init>.*|" +
    ".*Paths\\.get.*|" +
    ".*Path\\.of.*|" +
    ".*Path\\.resolve.*|" +
    ".*Files\\.readAllBytes.*|" +
    ".*Files\\.readAllLines.*|" +
    ".*Files\\.readString.*|" +
    ".*Files\\.newInputStream.*|" +
    ".*Files\\.newOutputStream.*|" +
    ".*Files\\.write.*|" +
    ".*Files\\.writeString.*|" +
    ".*Files\\.delete.*|" +
    ".*Files\\.deleteIfExists.*|" +
    ".*Files\\.copy.*|" +
    ".*Files\\.move.*|" +
    ".*FileUtils\\.(readFileTo|write|copyFile|delete|openInputStream|openOutputStream).*|" +
    ".*ServletContext\\.(getResource|getResourceAsStream|getRealPath).*|" +
    ".*UrlResource\\.<init>.*|" +
    ".*FileSystemResource\\.<init>.*|" +
    ".*PathResource\\.<init>.*|" +
    ".*ResourceUtils\\.getFile.*"

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
