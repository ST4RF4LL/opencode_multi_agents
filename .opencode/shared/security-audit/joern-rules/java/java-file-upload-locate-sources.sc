// Locate common external input sources for unsafe file upload.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sourcePattern =
  ".*MultipartFile\\.getOriginalFilename.*|" +
  ".*MultipartFile\\.getContentType.*|" +
  ".*MultipartFile\\.getBytes.*|" +
  ".*MultipartFile\\.getInputStream.*|" +
  ".*Part\\.getSubmittedFileName.*|" +
  ".*Part\\.getContentType.*|" +
  ".*Part\\.getInputStream.*|" +
  ".*FileItem\\.getName.*|" +
  ".*FileItem\\.getContentType.*|" +
  ".*FileItem\\.getInputStream.*|" +
  ".*FileItem\\.get.*|" +
  ".*HttpServletRequest\\.getPart.*|" +
  ".*HttpServletRequest\\.getParts.*|" +
  ".*ServletFileUpload\\.parseRequest.*"

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
  .where(_.annotation.name("RequestPart|RequestParam|RequestBody|PathVariable"))
  .l

annotated.foreach { p =>
  println(
    s"source_candidate\tfile=${p.file.name.headOption.getOrElse("?")}\t" +
    s"line=${p.lineNumber.getOrElse(-1)}\t" +
    s"method=${p.method.fullName}\t" +
    s"source=annotation:${p.annotation.name.mkString(",")}\t" +
    s"code=${p.name}"
  )
}

println(s"total_source_candidates=${sources.size + annotated.size}")
