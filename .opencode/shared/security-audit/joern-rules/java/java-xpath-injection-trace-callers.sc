// Expand callers from a sink method to build call chains (L1/L2 assist).

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String, sinkMethod: String = ".*XPath\\.compile.*")
// Do not call importCpg; use the ambient `cpg` symbol.
// Extra param default inlined: sinkMethod: String = ".*XPath\\.compile.*"

val sinkMethod = ".*XPath\\.compile.*"

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
