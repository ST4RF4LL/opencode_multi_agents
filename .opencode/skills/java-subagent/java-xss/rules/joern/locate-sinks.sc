// L1: locate XSS-related response/template sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinkPattern =
    ".*PrintWriter\\.print.*|" +
    ".*PrintWriter\\.println.*|" +
    ".*PrintWriter\\.write.*|" +
    ".*PrintWriter\\.append.*|" +
    ".*ServletOutputStream\\.print.*|" +
    ".*ServletOutputStream\\.write.*|" +
    ".*HttpServletResponse\\.sendError.*|" +
    ".*HttpServletResponse\\.getWriter.*|" +
    ".*Model\\.addAttribute.*|" +
    ".*ModelMap\\.addAttribute.*|" +
    ".*ModelAndView\\.addObject.*|" +
    ".*RedirectAttributes\\.addFlashAttribute.*"

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

  println(s"total_sink_candidates=${sinks.size}")
}
