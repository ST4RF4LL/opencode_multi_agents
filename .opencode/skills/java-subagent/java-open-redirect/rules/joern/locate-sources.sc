// Locate common external input sources for Java web apps (open redirect).
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sourcePattern =
    ".*HttpServletRequest\\.getParameter.*|" +
    ".*HttpServletRequest\\.getHeader.*|" +
    ".*HttpServletRequest\\.getQueryString.*|" +
    ".*HttpServletRequest\\.getPathInfo.*|" +
    ".*HttpServletRequest\\.getRequestURL.*"

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
    .where(_.annotation.name("RequestParam|PathVariable|RequestHeader|RequestBody|CookieValue"))
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
}
