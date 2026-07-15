// L2: track string/byte literals into secret-binding sinks.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val literals = cpg.literal

val secretSinks = cpg.call
  .methodFullName(
    ".*SecretKeySpec\\.<init>.*|" +
    ".*PBEKeySpec\\.<init>.*|" +
    ".*DriverManager\\.getConnection.*|" +
    ".*BasicAWSCredentials\\.<init>.*|" +
    ".*AwsBasicCredentials\\.create.*|" +
    ".*hmacShaKeyFor.*|" +
    ".*setSigningKey.*|" +
    ".*signWith.*"
  )
  .argument

val flows = secretSinks.reachableByFlows(literals).l

flows.zipWithIndex.foreach { case (flow, idx) =>
  println(s"dataflow_id=SECRET-LIT-FLOW-$idx")
  flow.elements.foreach { e =>
    println(
      s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
      s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code.take(160)}"
    )
  }
}

// Fields named like secrets used in calls
val secretFields = cpg.member
  .name("(?i).*(password|secret|apiKey|api_key|token|accessKey|privateKey).*")
val fieldUses = cpg.call.argument.where(_.isIdentifier.name("(?i).*(password|secret|apiKey|token|accessKey).*")).l
fieldUses.foreach { a =>
  println(
    s"dataflow_id=SECRET-FIELD-USE\tfile=${a.file.name.headOption.getOrElse("?")}\t" +
    s"line=${a.lineNumber.getOrElse(-1)}\tcode=${a.code}"
  )
}

// Heuristic: methods containing both literal and Authorization/password usage
val authMethods = cpg.method
  .where(_.code("(?i).*(authorization|api[_-]?key|password|secretkeyspec|getconnection).*"))
  .l
authMethods.foreach { m =>
  val hasLit = m.literal.nonEmpty
  if (hasLit) {
    println(
      s"dataflow_id=SECRET-METHOD-HEURISTIC\tmethod=${m.fullName}\t" +
      s"file=${m.filename}\tliterals=${m.literal.size}"
    )
  }
}

println(s"total_literal_to_sink_flows=${flows.size}")
println(s"total_secret_field_uses=${fieldUses.size}")
