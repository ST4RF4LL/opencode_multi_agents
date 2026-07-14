// L1: locate NoSQL-related sinks. Output SinkCandidate, not findings.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sinkPattern =
  ".*Document\\.parse.*|" +
  ".*BasicDBObject\\.parse.*|" +
  ".*BasicDBObject\\.<init>.*|" +
  ".*MongoCollection\\.find.*|" +
  ".*MongoCollection\\.delete.*|" +
  ".*MongoCollection\\.update.*|" +
  ".*MongoCollection\\.aggregate.*|" +
  ".*MongoCollection\\.countDocuments.*|" +
  ".*Filters\\.where.*|" +
  ".*MongoTemplate\\.find.*|" +
  ".*MongoTemplate\\.findOne.*|" +
  ".*MongoTemplate\\.remove.*|" +
  ".*MongoTemplate\\.update.*|" +
  ".*MongoTemplate\\.count.*|" +
  ".*BasicQuery\\.<init>.*|" +
  ".*Jedis\\.eval.*|" +
  ".*Jedis\\.evalsha.*"

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

// Literal $where usage in code
val whereLiterals = cpg.literal.code(".*\\$where.*").l
whereLiterals.foreach { lit =>
  println(
    s"sink_candidate\tfile=${lit.file.name.headOption.getOrElse("?")}\t" +
    s"line=${lit.lineNumber.getOrElse(-1)}\t" +
    s"method=${lit.method.fullName}\t" +
    s"sink=$where-literal\t" +
    s"code=${lit.code}"
  )
}

println(s"total_sink_candidates=${sinks.size + whereLiterals.size}")
