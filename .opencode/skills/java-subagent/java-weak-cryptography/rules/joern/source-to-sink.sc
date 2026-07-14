// L2: track algorithm/key/IV strings and password -> digest flows.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  // Password-like sources to MessageDigest.digest
  val paramSources = cpg.call
    .methodFullName(".*HttpServletRequest\\.getParameter.*")
    .argument

  val annotatedSources = cpg.parameter
    .where(_.annotation.name("RequestParam|RequestBody|PathVariable"))

  val digestSinks = cpg.call
    .methodFullName(".*MessageDigest\\.digest.*|.*DigestUtils\\.(md5|sha1|sha256|md5Hex|sha1Hex|sha256Hex).*")
    .argument

  val passwordFlows = (digestSinks.reachableByFlows(paramSources).l ++
    digestSinks.reachableByFlows(annotatedSources).l)

  passwordFlows.zipWithIndex.foreach { case (flow, idx) =>
    println(s"dataflow_id=CRYPTO-PWD-FLOW-$idx")
    flow.elements.foreach { e =>
      println(
        s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
        s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
      )
    }
  }

  // Random output used near SecretKeySpec / token assignment (heuristic adjacency)
  val randomCalls = cpg.call.methodFullName(".*java\\.util\\.Random\\.next.*|.*Math\\.random.*").l
  randomCalls.foreach { r =>
    val m = r.method
    val hasKeyUse = m.call.methodFullName(".*SecretKeySpec.*|.*IvParameterSpec.*").nonEmpty ||
      m.code.toLowerCase.matches(".*(token|session|secret|key|otp|csrf|nonce).*")
    if (hasKeyUse) {
      println(
        s"dataflow_id=CRYPTO-RANDOM-USE\tfile=${r.file.name.headOption.getOrElse("?")}\t" +
        s"line=${r.lineNumber.getOrElse(-1)}\tmethod=${m.fullName}\tcode=${r.code}"
      )
    }
  }

  // Literal weak algorithms flowing to Cipher.getInstance
  val cipherArgs = cpg.call.methodFullName(".*Cipher\\.getInstance.*").argument(1)
  val literals = cpg.literal
  val algoFlows = cipherArgs.reachableByFlows(literals).l
  algoFlows.zipWithIndex.foreach { case (flow, idx) =>
    println(s"dataflow_id=CRYPTO-ALGO-FLOW-$idx")
    flow.elements.foreach { e =>
      println(
        s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
        s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
      )
    }
  }

  println(s"total_password_digest_flows=${passwordFlows.size}")
  println(s"total_algo_literal_flows=${algoFlows.size}")
}
