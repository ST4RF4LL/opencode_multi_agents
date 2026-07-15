// Locate JWT token inputs and key/algorithm configuration sources.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val headers = cpg.call.methodFullName(".*HttpServletRequest\\.getHeader.*").l
headers.foreach { c =>
  println(
    s"token_source\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"kind=header\tcode=${c.code}"
  )
}

val params = cpg.call.methodFullName(".*HttpServletRequest\\.getParameter.*").l
params.foreach { c =>
  println(
    s"token_source\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"kind=parameter\tcode=${c.code}"
  )
}

val annotated = cpg.parameter
  .where(_.annotation.name("RequestParam|RequestBody|PathVariable|RequestHeader"))
  .l
annotated.foreach { p =>
  println(
    s"token_source\tfile=${p.file.name.headOption.getOrElse("?")}\t" +
    s"line=${p.lineNumber.getOrElse(-1)}\t" +
    s"kind=annotated_param\tname=${p.name}"
  )
}

val keyBinds = cpg.call.methodFullName(
  ".*setSigningKey.*|.*HMAC256.*|.*HMAC384.*|.*HMAC512.*|.*hmacShaKeyFor.*|.*MACVerifier\\.<init>.*"
).l
keyBinds.foreach { c =>
  println(
    s"config_source\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"kind=hmac_key_binding\tcode=${c.code}"
  )
}

val algNone = cpg.call.methodFullName(".*Algorithm\\.none.*|.*parseClaimsJwt.*|.*parseUnsecuredClaims.*").l
algNone.foreach { c =>
  println(
    s"config_source\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"kind=unsigned_or_none\tcode=${c.code}"
  )
}

println(s"total_header_sources=${headers.size}")
println(s"total_param_sources=${params.size}")
println(s"total_key_bindings=${keyBinds.size}")
println(s"total_unsigned_none=${algNone.size}")
