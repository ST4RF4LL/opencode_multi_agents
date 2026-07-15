// L2: source-to-sink dataflow for mass-assignment candidates (binding → save/copy).

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val annotatedSources = cpg.parameter
  .where(_.annotation.name("RequestBody|ModelAttribute|RequestPart"))

val servletSources = cpg.call.methodFullName(
  ".*HttpServletRequest\\.getParameter.*|" +
  ".*HttpServletRequest\\.getParameterMap.*"
).argument

val sinks = cpg.call.methodFullName(
  ".*CrudRepository\\.save.*|" +
  ".*JpaRepository\\.save.*|" +
  ".*JpaRepository\\.saveAndFlush.*|" +
  ".*EntityManager\\.(persist|merge).*|" +
  ".*BeanUtils\\.copyProperties.*|" +
  ".*PropertyUtils\\.copyProperties.*|" +
  ".*ObjectMapper\\.readerForUpdating.*|" +
  ".*ObjectMapper\\.updateValue.*|" +
  ".*JsonPatch\\.apply.*|" +
  ".*JsonMergePatch\\.apply.*"
).argument

val flowsFromParams = sinks.reachableByFlows(annotatedSources).l
val flowsFromCalls = sinks.reachableByFlows(servletSources).l
val flows = flowsFromParams ++ flowsFromCalls

flows.zipWithIndex.foreach { case (flow, idx) =>
  println(s"dataflow_id=MASS-ASSIGN-FLOW-$idx")
  flow.elements.foreach { e =>
    println(
      s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
      s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
    )
  }
}

// Sensitive field write hints on types used as binding targets
val sensitiveSetters = cpg.method
  .name("setAdmin|setRole|setRoles|setBalance|setOwnerId|setAuthorities|setVerified|setEnabled")
  .l

sensitiveSetters.foreach { m =>
  println(
    s"sensitive_setter\ttype=${m.typeDecl.fullName}\t" +
    s"method=${m.name}\tfile=${m.filename}\tline=${m.lineNumber.getOrElse(-1)}"
  )
}

println(s"total_flows=${flows.size}")
println(s"total_sensitive_setters=${sensitiveSetters.size}")
