// L2: token/header sources -> JWT parse/decode; secrets -> HMAC binders.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val tokenSources = cpg.call
    .methodFullName(".*HttpServletRequest\\.getHeader.*|.*HttpServletRequest\\.getParameter.*")
    .argument

  val annotatedSources = cpg.parameter
    .where(_.annotation.name("RequestParam|RequestBody|PathVariable|RequestHeader"))

  val parseSinks = cpg.call
    .methodFullName(
      ".*parseClaimsJws.*|.*parseClaimsJwt.*|.*parseSignedClaims.*|.*parseUnsecuredClaims.*|" +
      ".*SignedJWT\\.parse.*|.*JWTParser\\.parse.*|" +
      ".*com\\.auth0\\.jwt\\.JWT\\.decode.*|.*JWTVerifier\\.verify.*|" +
      ".*JwtDecoder\\.decode.*|.*DefaultJWTProcessor\\.process.*"
    )
    .argument

  val tokenFlows = (parseSinks.reachableByFlows(tokenSources).l ++
    parseSinks.reachableByFlows(annotatedSources).l)

  tokenFlows.zipWithIndex.foreach { case (flow, idx) =>
    println(s"dataflow_id=JWT-TOKEN-FLOW-$idx")
    flow.elements.foreach { e =>
      println(
        s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
        s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
      )
    }
  }

  // Literal secrets to HMAC APIs
  val hmacArgs = cpg.call
    .methodFullName(".*HMAC256.*|.*setSigningKey.*|.*hmacShaKeyFor.*|.*MACVerifier\\.<init>.*")
    .argument
  val litFlows = hmacArgs.reachableByFlows(cpg.literal).l
  litFlows.zipWithIndex.foreach { case (flow, idx) =>
    println(s"dataflow_id=JWT-SECRET-FLOW-$idx")
    flow.elements.foreach { e =>
      println(
        s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
        s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
      )
    }
  }

  // Parse without verify heuristic: method has decode/parse but no verify
  val decodeOnly = cpg.call.methodFullName(".*JWT\\.decode.*|.*parseClaimsJwt.*|.*parseUnsecuredClaims.*").l
  decodeOnly.foreach { d =>
    val m = d.method
    val hasVerify = m.call.methodFullName(".*verify.*|.*parseClaimsJws.*|.*parseSignedClaims.*|.*process.*").nonEmpty
    if (!hasVerify) {
      println(
        s"dataflow_id=JWT-DECODE-NO-VERIFY\tfile=${d.file.name.headOption.getOrElse("?")}\t" +
        s"line=${d.lineNumber.getOrElse(-1)}\tmethod=${m.fullName}\tcode=${d.code}"
      )
    }
  }

  println(s"total_token_flows=${tokenFlows.size}")
  println(s"total_secret_literal_flows=${litFlows.size}")
}
