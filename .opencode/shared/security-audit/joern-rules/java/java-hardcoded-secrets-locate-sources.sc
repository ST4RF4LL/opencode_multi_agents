// Locate secret material introduction points (literals, constants, config-like fields).

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

// String literals assigned to fields/locals with secret-ish names
val fields = cpg.member
  .name("(?i).*(password|passwd|secret|apiKey|api_key|token|privateKey|accessKey|clientSecret).*")
  .l

fields.foreach { f =>
  println(
    s"config_source\tfile=${f.file.name.headOption.getOrElse("?")}\t" +
    s"line=${f.lineNumber.getOrElse(-1)}\t" +
    s"kind=field\tname=${f.name}\tcode=${f.code.take(160)}"
  )
}

// SecretKeySpec first argument
val keySpecs = cpg.call.methodFullName(".*SecretKeySpec\\.<init>.*").l
keySpecs.foreach { c =>
  println(
    s"config_source\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"kind=key_material\tcode=${c.code}"
  )
}

// DriverManager credentials
val jdbc = cpg.call.methodFullName(".*DriverManager\\.getConnection.*").l
jdbc.foreach { c =>
  println(
    s"config_source\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"kind=jdbc_credentials\tcode=${c.code}"
  )
}

// AWS static credentials
val aws = cpg.call.methodFullName(
  ".*BasicAWSCredentials\\.<init>.*|.*AwsBasicCredentials\\.create.*"
).l
aws.foreach { c =>
  println(
    s"config_source\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"kind=cloud_credentials\tcode=${c.code}"
  )
}

// Env lookups (externalized — not secret sources themselves)
val env = cpg.call.methodFullName(".*System\\.getenv.*|.*System\\.getProperty.*").l
env.foreach { c =>
  println(
    s"external_source\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"kind=env_or_property\tcode=${c.code}"
  )
}

println(s"total_secret_fields=${fields.size}")
println(s"total_key_specs=${keySpecs.size}")
println(s"total_jdbc=${jdbc.size}")
println(s"total_aws_cred=${aws.size}")
