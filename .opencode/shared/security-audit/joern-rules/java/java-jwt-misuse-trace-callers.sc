// Expand callers from JWT sink methods to build call chains.

  val methods = cpg.method.fullName(sinkMethod).l
  methods.foreach { m =>
    println(s"sink_method=${m.fullName}")
    m.caller.foreach { c =>
      println(s"  caller=${c.fullName}\tfile=${c.filename}\tline=${c.lineNumber.getOrElse(-1)}")
      c.caller.take(20).foreach { cc =>
        println(s"    caller2=${cc.fullName}\tfile=${cc.filename}")
      }
    }
  }

  val related = cpg.call.methodFullName(
    ".*parseClaimsJws.*|.*parseClaimsJwt.*|.*JWT\\.decode.*|.*JWTVerifier\\.verify.*|" +
    ".*SignedJWT\\.parse.*|.*JwtDecoder\\.decode.*|.*setSigningKey.*|.*HMAC256.*"
  ).method.l.distinct

  related.foreach { m =>
    println(s"jwt_user_method=${m.fullName}\tfile=${m.filename}")
  }
}
