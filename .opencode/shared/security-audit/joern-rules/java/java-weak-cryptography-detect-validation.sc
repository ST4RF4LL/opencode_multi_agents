// L3 assist: find strong crypto patterns vs weak nearby controls.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val cipherCalls = cpg.call.methodFullName(".*Cipher\\.getInstance.*").l

cipherCalls.foreach { s =>
  val m = s.method
  val algo = s.argument(1).code.headOption.getOrElse("?")
  val hasGcm = m.code.contains("GCM") || algo.contains("GCM")
  val hasIvSpec = m.call.methodFullName(".*IvParameterSpec.*|.*GCMParameterSpec.*").nonEmpty
  val hasSecureRandom = m.call.methodFullName(".*SecureRandom.*").nonEmpty
  val hasUtilRandom = m.call.methodFullName(".*java\\.util\\.Random.*").nonEmpty
  val hasSecretKeySpec = m.call.methodFullName(".*SecretKeySpec.*").nonEmpty
  val hasHardcodedBytes = m.literal.code(".*").l.exists { lit =>
    lit.code.matches(".*\\{.*\\d+.*\\}.*") && m.code.contains("SecretKeySpec")
  }

  println(
    s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
    s"line=${s.lineNumber.getOrElse(-1)}\t" +
    s"method=${m.fullName}\t" +
    s"algo=$algo\t" +
    s"has_gcm=$hasGcm\t" +
    s"has_iv_spec=$hasIvSpec\t" +
    s"has_securerandom=$hasSecureRandom\t" +
    s"has_util_random=$hasUtilRandom\t" +
    s"has_secretkeyspec=$hasSecretKeySpec\t" +
    s"hardcoded_bytes_hint=$hasHardcodedBytes"
  )
}

// Password encoder / digest context
val digests = cpg.call.methodFullName(".*MessageDigest\\.getInstance.*").l
digests.foreach { d =>
  val m = d.method
  val algo = d.argument(1).code.headOption.getOrElse("?")
  val mentionsPassword = m.code.toLowerCase.contains("password") ||
    m.name.toLowerCase.matches(".*(password|passwd|pwd|credential).*")
  println(
    s"digest_context\tfile=${d.file.name.headOption.getOrElse("?")}\t" +
    s"line=${d.lineNumber.getOrElse(-1)}\t" +
    s"method=${m.fullName}\t" +
    s"algo=$algo\t" +
    s"password_context=$mentionsPassword"
  )
}
