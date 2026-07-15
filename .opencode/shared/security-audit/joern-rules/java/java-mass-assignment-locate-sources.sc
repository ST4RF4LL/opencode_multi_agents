// Locate external input sources relevant to mass assignment / over-posting.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sourcePattern =
  ".*HttpServletRequest\\.getParameter.*|" +
  ".*HttpServletRequest\\.getParameterMap.*|" +
  ".*HttpServletRequest\\.getParameterValues.*|" +
  ".*ObjectMapper\\.readValue.*|" +
  ".*ObjectReader\\.readValue.*"

val sources = cpg.call.methodFullName(sourcePattern).l

sources.foreach { c =>
  println(
    s"source_candidate\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"method=${c.method.fullName}\t" +
    s"source=${c.methodFullName}\t" +
    s"code=${c.code}"
  )
}

val annotated = cpg.parameter
  .where(_.annotation.name("RequestBody|ModelAttribute|RequestPart|RequestParam"))
  .l

annotated.foreach { p =>
  println(
    s"source_candidate\tfile=${p.file.name.headOption.getOrElse("?")}\t" +
    s"line=${p.lineNumber.getOrElse(-1)}\t" +
    s"method=${p.method.fullName}\t" +
    s"source=annotation:${p.annotation.name.mkString(",")}\t" +
    s"type=${p.typeFullName}\t" +
    s"code=${p.name}"
  )
}

println(s"total_source_candidates=${sources.size + annotated.size}")
