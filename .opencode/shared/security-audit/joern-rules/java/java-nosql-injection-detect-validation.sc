// L3 assist: find nearby validation / query-builder patterns around NoSQL sinks.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sinks = cpg.call.methodFullName(
  ".*Document\\.parse.*|" +
  ".*BasicDBObject\\.parse.*|" +
  ".*MongoCollection\\.find.*|" +
  ".*Filters\\.where.*|" +
  ".*MongoTemplate\\.(find|findOne|remove|update).*|" +
  ".*BasicQuery\\.<init>.*"
).l

sinks.foreach { s =>
  val m = s.method
  val hasFiltersEq = m.call.name("eq|gt|lt|and|or").nonEmpty ||
    m.code.contains("Filters.eq") || m.code.contains("Filters.")
  val hasAllowlist = m.call.name("contains|equals|valueOf|fromValue|matches").nonEmpty
  val hasRejectSpecial = m.code.contains("$") && (
    m.call.name("contains|replace|replaceAll|matches|reject").nonEmpty
  )
  val hasParse = m.call.methodFullName(".*Document\\.parse.*|.*BasicDBObject\\.parse.*").nonEmpty
  val hasConcat = m.call.name("concat|format|append").nonEmpty || m.code.contains("+")

  println(
    s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
    s"line=${s.lineNumber.getOrElse(-1)}\t" +
    s"method=${m.fullName}\t" +
    s"has_filters_api=$hasFiltersEq\t" +
    s"has_allowlist_like=$hasAllowlist\t" +
    s"has_special_char_check=$hasRejectSpecial\t" +
    s"has_document_parse=$hasParse\t" +
    s"has_concat_hint=$hasConcat\t" +
    s"sink=${s.methodFullName}"
  )
}
