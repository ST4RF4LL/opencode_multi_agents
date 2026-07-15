// L1: locate deserialization sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*ObjectInputStream\\.readObject.*|" +
    ".*ObjectInputStream\\.readUnshared.*|" +
    ".*XMLDecoder\\.readObject.*|" +
    ".*com\\.alibaba\\.fastjson\\.JSON\\.parse.*|" +
    ".*com\\.alibaba\\.fastjson\\.JSON\\.parseObject.*|" +
    ".*com\\.alibaba\\.fastjson2\\.JSON\\.parse.*|" +
    ".*com\\.alibaba\\.fastjson2\\.JSON\\.parseObject.*|" +
    ".*ObjectMapper\\.readValue.*|" +
    ".*ObjectMapper\\.enableDefaultTyping.*|" +
    ".*ObjectMapper\\.activateDefaultTyping.*|" +
    ".*org\\.yaml\\.snakeyaml\\.Yaml\\.load.*|" +
    ".*org\\.yaml\\.snakeyaml\\.Yaml\\.loadAll.*|" +
    ".*org\\.yaml\\.snakeyaml\\.Yaml\\.loadAs.*|" +
    ".*XStream\\.fromXML.*|" +
    ".*XStream\\.unmarshal.*|" +
    ".*Hessian2Input\\.readObject.*|" +
    ".*HessianInput\\.readObject.*|" +
    ".*Kryo\\.readObject.*|" +
    ".*Kryo\\.readClassAndObject.*|" +
    ".*JdkSerializationRedisSerializer\\.deserialize.*|" +
    ".*SerializationUtils\\.deserialize.*"

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

  // Config-style danger signals (not findings alone)
  val configHits = cpg.call.methodFullName(
    ".*ParserConfig\\.setAutoTypeSupport.*|" +
    ".*ObjectMapper\\.enableDefaultTyping.*|" +
    ".*ObjectMapper\\.activateDefaultTyping.*"
  ).l
  configHits.foreach { c =>
    println(
      s"config_signal\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
      s"line=${c.lineNumber.getOrElse(-1)}\t" +
      s"method=${c.method.fullName}\t" +
      s"signal=${c.methodFullName}\t" +
      s"code=${c.code}"
    )
  }

  println(s"total_sink_candidates=${sinks.size}")
  println(s"total_config_signals=${configHits.size}")
}
