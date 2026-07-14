// L1: locate crypto-related sinks. Output CryptoCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*Cipher\\.getInstance.*|" +
    ".*Cipher\\.init.*|" +
    ".*MessageDigest\\.getInstance.*|" +
    ".*MessageDigest\\.digest.*|" +
    ".*Mac\\.getInstance.*|" +
    ".*Signature\\.getInstance.*|" +
    ".*SecretKeySpec\\.<init>.*|" +
    ".*IvParameterSpec\\.<init>.*|" +
    ".*GCMParameterSpec\\.<init>.*|" +
    ".*KeyGenerator\\.getInstance.*|" +
    ".*KeyPairGenerator\\.getInstance.*|" +
    ".*SecretKeyFactory\\.getInstance.*|" +
    ".*SecureRandom\\.<init>.*|" +
    ".*SecureRandom\\.setSeed.*|" +
    ".*java\\.util\\.Random\\.<init>.*|" +
    ".*java\\.util\\.Random\\.next.*"

  val sinks = cpg.call.methodFullName(sinkPattern).l

  sinks.foreach { c =>
    println(
      s"crypto_candidate\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
      s"line=${c.lineNumber.getOrElse(-1)}\t" +
      s"method=${c.method.fullName}\t" +
      s"sink=${c.methodFullName}\t" +
      s"code=${c.code}"
    )
  }

  // Algorithm string literals near Cipher/MessageDigest
  val weakAlgos = cpg.literal.code(
    ".*DES.*|.*DESede.*|.*RC4.*|.*AES/ECB.*|.*\"AES\".*|.*MD5.*|.*SHA-1.*|.*SHA1.*|.*PKCS1Padding.*"
  ).l

  weakAlgos.foreach { lit =>
    println(
      s"algo_literal\tfile=${lit.file.name.headOption.getOrElse("?")}\t" +
      s"line=${lit.lineNumber.getOrElse(-1)}\t" +
      s"code=${lit.code}"
    )
  }

  println(s"total_crypto_candidates=${sinks.size}")
  println(s"total_algo_literals=${weakAlgos.size}")
}
