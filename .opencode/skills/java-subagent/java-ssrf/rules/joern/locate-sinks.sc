// L1: locate SSRF-related network sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*URL\\.openConnection.*|" +
    ".*URL\\.openStream.*|" +
    ".*URL\\.getContent.*|" +
    ".*HttpURLConnection\\.(connect|getInputStream).*|" +
    ".*RestTemplate\\.(exchange|getForObject|getForEntity|postForObject|postForEntity|execute).*|" +
    ".*WebClient\\..*uri.*|" +
    ".*HttpClient\\.execute.*|" +
    ".*CloseableHttpClient\\.execute.*|" +
    ".*HttpGet\\.<init>.*|" +
    ".*HttpPost\\.<init>.*|" +
    ".*Request\\.Builder\\.url.*|" +
    ".*OkHttpClient\\.newCall.*|" +
    ".*HttpRequest\\.Builder\\.uri.*|" +
    ".*java\\.net\\.http\\.HttpClient\\.send.*"

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
