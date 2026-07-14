// Locate crypto configuration sources and sensitive inputs.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  // Algorithm arguments to getInstance
  val algoArgs = cpg.call
    .methodFullName(".*Cipher\\.getInstance.*|.*MessageDigest\\.getInstance.*|.*Mac\\.getInstance.*|.*Signature\\.getInstance.*")
    .argument(1)
    .l

  algoArgs.foreach { a =>
    println(
      s"config_source\tfile=${a.file.name.headOption.getOrElse("?")}\t" +
      s"line=${a.lineNumber.getOrElse(-1)}\t" +
      s"kind=algorithm_arg\tcode=${a.code}"
    )
  }

  // Hardcoded byte arrays / string getBytes near key construction
  val keySpecs = cpg.call.methodFullName(".*SecretKeySpec\\.<init>.*").l
  keySpecs.foreach { c =>
    println(
      s"config_source\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
      s"line=${c.lineNumber.getOrElse(-1)}\t" +
      s"kind=key_material\tcode=${c.code}"
    )
  }

  val ivSpecs = cpg.call.methodFullName(".*IvParameterSpec\\.<init>.*|.*GCMParameterSpec\\.<init>.*").l
  ivSpecs.foreach { c =>
    println(
      s"config_source\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
      s"line=${c.lineNumber.getOrElse(-1)}\t" +
      s"kind=iv_nonce\tcode=${c.code}"
    )
  }

  // Weak PRNG
  val randoms = cpg.call.methodFullName(".*java\\.util\\.Random\\.<init>.*|.*Math\\.random.*").l
  randoms.foreach { c =>
    println(
      s"config_source\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
      s"line=${c.lineNumber.getOrElse(-1)}\t" +
      s"kind=weak_prng\tcode=${c.code}"
    )
  }

  // Password-like request params (for weak-password-hash)
  val params = cpg.call.methodFullName(".*HttpServletRequest\\.getParameter.*").l
  params.foreach { c =>
    println(
      s"sensitive_input\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
      s"line=${c.lineNumber.getOrElse(-1)}\t" +
      s"kind=request_param\tcode=${c.code}"
    )
  }

  println(s"total_algo_args=${algoArgs.size}")
  println(s"total_key_specs=${keySpecs.size}")
  println(s"total_iv_specs=${ivSpecs.size}")
  println(s"total_weak_prng=${randoms.size}")
}
