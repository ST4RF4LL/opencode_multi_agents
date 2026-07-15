// L3 assist: distinguish placeholders, env usage, and hardcoded bindings.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

  val keySpecs = cpg.call.methodFullName(".*SecretKeySpec\\.<init>.*").l
  keySpecs.foreach { s =>
    val m = s.method
    val code = s.code
    val hasEnv = m.call.methodFullName(".*System\\.getenv.*|.*System\\.getProperty.*|.*Environment\\.getProperty.*").nonEmpty
    val lit = s.argument(1).code.headOption.getOrElse("?")
    val placeholder =
      lit.matches("(?i).*(CHANGE_ME|your-api-key|TODO|XXXX|NOT_REAL|EXAMPLE|\\$\\{).*")
    println(
      s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
      s"line=${s.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"kind=SecretKeySpec\t" +
      s"has_env=$hasEnv\t" +
      s"placeholder_hint=$placeholder\t" +
      s"arg=${lit.take(80)}"
    )
  }

  val jdbc = cpg.call.methodFullName(".*DriverManager\\.getConnection.*").l
  jdbc.foreach { s =>
    val m = s.method
    val hasEnv = m.call.methodFullName(".*System\\.getenv.*|.*System\\.getProperty.*").nonEmpty
    val hasLit = s.argument.isLiteral.nonEmpty || s.argument.code.exists(_.contains("\""))
    println(
      s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
      s"line=${s.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"kind=jdbc\t" +
      s"has_env=$hasEnv\t" +
      s"has_literal_hint=$hasLit"
    )
  }

  val aws = cpg.call.methodFullName(
    ".*BasicAWSCredentials\\.<init>.*|.*AwsBasicCredentials\\.create.*"
  ).l
  aws.foreach { s =>
    val m = s.method
    val code = s.code
    val docsExample = code.contains("AKIAIOSFODNN7EXAMPLE") ||
      code.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    val hasEnv = m.call.methodFullName(".*System\\.getenv.*").nonEmpty
    println(
      s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
      s"line=${s.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"kind=aws_static\t" +
      s"docs_example=$docsExample\t" +
      s"has_env=$hasEnv"
    )
  }

  // Constants that look like API keys
  val apiConsts = cpg.assignment
    .where(_.target.isIdentifier.name("(?i).*(API_?KEY|SECRET|TOKEN|PASSWORD).*"))
    .l
  apiConsts.foreach { a =>
    val rhs = a.source.code
    val placeholder = rhs.matches("(?i).*(CHANGE_ME|EXAMPLE|your-|TODO|NOT_REAL|\\$\\{).*")
    println(
      s"control_context\tfile=${a.file.name.headOption.getOrElse("?")}\t" +
      s"line=${a.lineNumber.getOrElse(-1)}\t" +
      s"kind=named_constant\t" +
      s"placeholder_hint=$placeholder\t" +
      s"code=${a.code.take(120)}"
    )
  }
}
