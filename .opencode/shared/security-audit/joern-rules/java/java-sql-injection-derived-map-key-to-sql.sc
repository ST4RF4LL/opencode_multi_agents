// Derived from: CVE-2025-65896 / GHSA-qhqw-rrw9-25rm (asyncmy dict key SQLi)
// Pattern: Map keys used as SQL identifiers while values may be escaped/bound.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

// Iteration over map entries / keySet often precedes dynamic column SQL
val mapIters = cpg.call.methodFullName(
  ".*Map\\.keySet.*|" +
  ".*Map\\.entrySet.*|" +
  ".*Map\\.forEach.*|" +
  ".*Map\\.get.*"
).l

val sqlBuilders = cpg.call.name("append|concat|format").l
val sqlSinks = cpg.call.methodFullName(
  ".*Statement\\.execute.*|" +
  ".*prepareStatement.*|" +
  ".*JdbcTemplate\\.(query|update|execute).*|" +
  ".*createNativeQuery.*|" +
  ".*createQuery.*"
).l

// Methods that both iterate maps and touch SQL sinks
val suspectMethods = (mapIters.map(_.method).toSet intersect sqlSinks.map(_.method).toSet).toList

suspectMethods.foreach { m =>
  val hasEscapeOrSet =
    m.call.name("setString|setObject|setParameter|escape|quote|replace").nonEmpty
  println(
    s"pattern=map-key-to-sql\t" +
    s"file=${m.filename}\t" +
    s"method=${m.fullName}\t" +
    s"has_value_binding_or_escape=$hasEscapeOrSet\t" +
    s"note=review_whether_map_keys_are_allowlisted"
  )
  m.call.methodFullName(".*Statement\\..*|.*prepareStatement.*|.*JdbcTemplate\\..*|.*createNativeQuery.*|.*createQuery.*").foreach { c =>
    println(s"  sink_line=${c.lineNumber.getOrElse(-1)}\tcode=${c.code}")
  }
}

// Dataflow: getKey() / next() style keys into string builders used by SQL (heuristic)
val keySources = cpg.call.methodFullName(".*Map\\.Entry\\.getKey.*|.*Entry\\.getKey.*").l
keySources.foreach { k =>
  val nearby = k.method.call.name("append|concat|format").l
  if (nearby.nonEmpty && k.method.call.methodFullName(".*execute.*|.*prepareStatement.*|.*query.*|.*createNativeQuery.*").nonEmpty) {
    println(
      s"pattern=map-key-to-sql-getKey\t" +
      s"file=${k.file.name.headOption.getOrElse("?")}\t" +
      s"line=${k.lineNumber.getOrElse(-1)}\t" +
      s"method=${k.method.fullName}\tcode=${k.code}"
    )
  }
}

println("done=map-key-to-sql")
