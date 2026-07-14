// Expand callers from crypto sink methods to build call chains.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String, sinkMethod: String = ".*Cipher\\.getInstance.*")
// Do not call importCpg; use the ambient `cpg` symbol.
// Extra param default inlined: sinkMethod: String = ".*Cipher\\.getInstance.*"

val sinkMethod = ".*Cipher\\.getInstance.*"

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

// Also show methods that call Cipher.init / MessageDigest
val related = cpg.call.methodFullName(
  ".*Cipher\\.(getInstance|init|doFinal).*|.*MessageDigest\\.(getInstance|digest).*"
).method.l.distinct

related.foreach { m =>
  println(s"crypto_user_method=${m.fullName}\tfile=${m.filename}")
}
