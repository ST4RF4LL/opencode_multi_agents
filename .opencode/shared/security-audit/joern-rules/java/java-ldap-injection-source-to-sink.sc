// L2: source-to-sink dataflow for LDAP injection candidates.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sourceCalls = cpg.call.methodFullName(
  ".*HttpServletRequest\\.getParameter.*|" +
  ".*HttpServletRequest\\.getHeader.*|" +
  ".*Authentication\\.getName.*"
).argument

val annotatedSources = cpg.parameter
  .where(_.annotation.name("RequestParam|PathVariable|RequestHeader|RequestBody"))

val sinks = cpg.call.methodFullName(
  ".*DirContext\\.search.*|" +
  ".*InitialDirContext\\.search.*|" +
  ".*Context\\.lookup.*|" +
  ".*Context\\.bind.*|" +
  ".*LdapTemplate\\.search.*|" +
  ".*LdapTemplate\\.authenticate.*|" +
  ".*LdapTemplate\\.lookup.*|" +
  ".*LdapTemplate\\.find.*|" +
  ".*HardcodedFilter\\..*|" +
  ".*LDAPConnection\\.search.*"
).argument

val flowsFromCalls = sinks.reachableByFlows(sourceCalls).l
val flowsFromParams = sinks.reachableByFlows(annotatedSources).l
val flows = flowsFromCalls ++ flowsFromParams

flows.zipWithIndex.foreach { case (flow, idx) =>
  println(s"dataflow_id=LDAP-FLOW-$idx")
  flow.elements.foreach { e =>
    println(
      s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
      s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
    )
  }
}

println(s"total_flows=${flows.size}")
