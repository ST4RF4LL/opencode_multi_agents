// L3 assist: signature verify, algorithm lock, claim validation context.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val parseCalls = cpg.call.methodFullName(
  ".*parseClaimsJws.*|.*parseClaimsJwt.*|.*parseSignedClaims.*|.*parseUnsecuredClaims.*|" +
  ".*SignedJWT\\.parse.*|.*JWT\\.decode.*|.*JwtDecoder\\.decode.*|.*JWTVerifier\\.verify.*"
).l

parseCalls.foreach { s =>
  val m = s.method
  val code = m.code
  val hasVerify = code.matches("(?s).*(verify|parseClaimsJws|parseSignedClaims|process\\().*")
  val hasUnsigned = code.matches("(?s).*(parseClaimsJwt|parseUnsecuredClaims|JWT\\.decode|Algorithm\\.none).*")
  val hasExp = code.toLowerCase.matches("(?s).*(getexpiration|requireexpiration|withexpiresat|acceptexpiresat|exp).*")
  val hasAud = code.toLowerCase.matches("(?s).*(getaudience|withaudience|audience).*")
  val hasIss = code.toLowerCase.matches("(?s).*(getissuer|withissuer|issuer).*")
  val hasHmacLit = code.matches("(?s).*(\"(secret|changeme|password)\"|HMAC256\\(\").*")
  val hasPublicAsHmac = code.matches("(?s).*(getPublicKey|getEncoded\\(\\)).*(HMAC|setSigningKey|MACVerifier|hmacShaKeyFor).*") ||
    code.matches("(?s).*(HMAC|setSigningKey|MACVerifier|hmacShaKeyFor).*(getPublicKey|getEncoded\\(\\)).*")

  println(
    s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
    s"line=${s.lineNumber.getOrElse(-1)}\t" +
    s"method=${m.fullName}\t" +
    s"has_verify=$hasVerify\t" +
    s"has_unsigned_path=$hasUnsigned\t" +
    s"has_exp=$hasExp\t" +
    s"has_aud=$hasAud\t" +
    s"has_iss=$hasIss\t" +
    s"hmac_literal_hint=$hasHmacLit\t" +
    s"public_key_hmac_hint=$hasPublicAsHmac"
  )
}

val claimGets = cpg.call.methodFullName(
  ".*getSubject.*|.*getClaim.*|.*getJWTClaimsSet.*|.*getBody.*|.*getPayload.*"
).l
claimGets.foreach { c =>
  val m = c.method
  val hasPriorVerify = m.call.methodFullName(
    ".*verify.*|.*parseClaimsJws.*|.*parseSignedClaims.*|.*process.*"
  ).nonEmpty
  println(
    s"claim_use\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"method=${m.fullName}\t" +
    s"prior_verify_in_method=$hasPriorVerify\t" +
    s"code=${c.code}"
  )
}
