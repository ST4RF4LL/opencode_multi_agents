// L1: locate open-redirect sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*HttpServletResponse\\.sendRedirect.*|" +
    ".*ServletResponse\\.sendRedirect.*|" +
    ".*HttpServletResponse\\.setHeader.*|" +
    ".*HttpServletResponse\\.addHeader.*|" +
    ".*RedirectView\\.<init>.*|" +
    ".*RedirectView\\.setUrl.*|" +
    ".*HttpHeaders\\.setLocation.*|" +
    ".*ResponseEntity\\..*location.*|" +
    ".*ModelAndView\\.setViewName.*|" +
    ".*ModelAndView\\.<init>.*"

  val sinks = cpg.call.methodFullName(sinkPattern).l

  sinks.foreach { c =>
    println(
      s"sink_candidate\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
      s"line=${c.lineNumber.getOrElse(-1)}\t" +
      s"method=${c.method.fullName}\t" +
      s"sink=${c.methodFullName}\t" +
      s"code=${c.code}"
    )
  }

  // Spring redirect: string returns (literal or concat hints in method code)
  val redirectViews = cpg.method
    .where(_.code("(?s).*redirect:.*"))
    .l

  redirectViews.foreach { m =>
    println(
      s"sink_candidate\tfile=${m.filename}\t" +
      s"line=${m.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"sink=spring-redirect-prefix\t" +
      s"code=redirect: pattern in method"
    )
  }

  println(s"total_sink_candidates=${sinks.size + redirectViews.size}")
}
