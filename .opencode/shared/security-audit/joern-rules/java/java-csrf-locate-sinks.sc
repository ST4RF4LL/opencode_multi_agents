// L1: locate CSRF-related sinks — state-changing endpoints and CSRF disable config.
// Output SinkCandidate, not findings.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val csrfDisable = cpg.call
  .code(".*csrf.*disable.*|.*AbstractHttpConfigurer::disable.*")
  .l

csrfDisable.foreach { c =>
  println(
    s"sink_candidate\tkind=csrf_disable\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"method=${c.method.fullName}\t" +
    s"code=${c.code}"
  )
}

val mutatingAnnos = cpg.annotation
  .name("PostMapping|PutMapping|DeleteMapping|PatchMapping")
  .l

mutatingAnnos.foreach { a =>
  val m = a.method
  println(
    s"sink_candidate\tkind=mutating_endpoint\tfile=${m.filename}\t" +
    s"line=${m.lineNumber.getOrElse(-1)}\t" +
    s"method=${m.fullName}\t" +
    s"annotation=${a.name}\tcode=${a.code}"
  )
}

val getAnnos = cpg.annotation.name("GetMapping").l
getAnnos.foreach { a =>
  val pathHint = a.code.toLowerCase
  val m = a.method
  val bodyHint = m.code.toLowerCase
  val suspicious =
    pathHint.contains("delete") || pathHint.contains("remove") ||
    pathHint.contains("logout") || pathHint.contains("transfer") ||
    pathHint.contains("update") ||
    bodyHint.contains("delete") || bodyHint.contains("remove") ||
    bodyHint.contains("updatepassword") || bodyHint.contains("transfer")
  if (suspicious) {
    println(
      s"sink_candidate\tkind=get_based_mutation\tfile=${m.filename}\t" +
      s"line=${m.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\tcode=${a.code}"
    )
  }
}

val stateWrites = cpg.call.methodFullName(
  ".*Repository\\.(save|delete|deleteById).*|" +
  ".*JdbcTemplate\\.(update|batchUpdate).*|" +
  ".*EntityManager\\.(persist|merge|remove).*|" +
  ".*HttpSession\\.(setAttribute|invalidate).*"
).l

stateWrites.foreach { c =>
  println(
    s"sink_candidate\tkind=state_write\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"method=${c.method.fullName}\t" +
    s"sink=${c.methodFullName}\tcode=${c.code}"
  )
}

println(
  s"total_sink_candidates=${csrfDisable.size + mutatingAnnos.size + stateWrites.size}"
)
