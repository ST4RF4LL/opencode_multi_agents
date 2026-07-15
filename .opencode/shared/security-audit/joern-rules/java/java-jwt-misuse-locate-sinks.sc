// L1: locate JWT-related sinks. Output JwtCandidate, not findings.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sinkPattern =
  ".*Jwts\\.parser.*|" +
  ".*JwtParser\\.parse.*|" +
  ".*parseClaimsJws.*|" +
  ".*parseClaimsJwt.*|" +
  ".*parseSignedClaims.*|" +
  ".*parseUnsecuredClaims.*|" +
  ".*setSigningKey.*|" +
  ".*verifyWith.*|" +
  ".*SignedJWT\\.parse.*|" +
  ".*JWTParser\\.parse.*|" +
  ".*SignedJWT\\.verify.*|" +
  ".*DefaultJWTProcessor\\.process.*|" +
  ".*MACVerifier\\.<init>.*|" +
  ".*RSASSAVerifier\\.<init>.*|" +
  ".*com\\.auth0\\.jwt\\.JWT\\.decode.*|" +
  ".*com\\.auth0\\.jwt\\.JWT\\.require.*|" +
  ".*JWTVerifier\\.verify.*|" +
  ".*Algorithm\\.HMAC.*|" +
  ".*Algorithm\\.none.*|" +
  ".*JwtDecoder\\.decode.*|" +
  ".*NimbusJwtDecoder.*"

val sinks = cpg.call.methodFullName(sinkPattern).l

sinks.foreach { c =>
  println(
    s"jwt_candidate\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"method=${c.method.fullName}\t" +
    s"sink=${c.methodFullName}\t" +
    s"code=${c.code}"
  )
}

val weakLits = cpg.literal.code(
  ".*secret.*|.*changeme.*|.*password.*|.*jwt-secret.*|.*\"none\".*|.*HS256.*|.*HS512.*"
).l

weakLits.foreach { lit =>
  println(
    s"jwt_literal\tfile=${lit.file.name.headOption.getOrElse("?")}\t" +
    s"line=${lit.lineNumber.getOrElse(-1)}\t" +
    s"code=${lit.code}"
  )
}

println(s"total_jwt_candidates=${sinks.size}")
println(s"total_jwt_literals=${weakLits.size}")
