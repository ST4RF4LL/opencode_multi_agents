// L1: locate secret-binding sinks. Output SecretCandidate, not findings.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sinkPattern =
  ".*SecretKeySpec\\.<init>.*|" +
  ".*PBEKeySpec\\.<init>.*|" +
  ".*KeyStore\\.load.*|" +
  ".*KeyStore\\.getKey.*|" +
  ".*DriverManager\\.getConnection.*|" +
  ".*setPassword.*|" +
  ".*BasicAWSCredentials\\.<init>.*|" +
  ".*AwsBasicCredentials\\.create.*|" +
  ".*StaticCredentialsProvider\\.create.*|" +
  ".*signWith.*|" +
  ".*setSigningKey.*|" +
  ".*hmacShaKeyFor.*"

val sinks = cpg.call.methodFullName(sinkPattern).l

sinks.foreach { c =>
  println(
    s"secret_candidate\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"method=${c.method.fullName}\t" +
    s"sink=${c.methodFullName}\t" +
    s"code=${c.code}"
  )
}

// Secret-shaped string literals
val secretLits = cpg.literal.code(
  ".*AKIA[0-9A-Z]{16}.*|" +
  ".*BEGIN.*PRIVATE KEY.*|" +
  ".*password.*|" +
  ".*secret.*|" +
  ".*api[_-]?key.*"
).l

secretLits.foreach { lit =>
  println(
    s"secret_literal\tfile=${lit.file.name.headOption.getOrElse("?")}\t" +
    s"line=${lit.lineNumber.getOrElse(-1)}\t" +
    s"code=${lit.code.take(120)}"
  )
}

println(s"total_secret_candidates=${sinks.size}")
println(s"total_secret_literals=${secretLits.size}")
