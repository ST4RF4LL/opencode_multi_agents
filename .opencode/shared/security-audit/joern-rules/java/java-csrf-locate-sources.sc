// Locate session/cookie authentication sources relevant to CSRF.
// CSRF "source" is browser auto-credentials + attacker-controlled request parameters.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sessionCalls = cpg.call.methodFullName(
  ".*HttpServletRequest\\.getSession.*|" +
  ".*HttpSession\\.getAttribute.*|" +
  ".*HttpSession\\.setAttribute.*|" +
  ".*SecurityContextHolder\\.getContext.*|" +
  ".*HttpServletRequest\\.getCookies.*"
).l

sessionCalls.foreach { c =>
  println(
    s"source_candidate\tkind=session_or_cookie\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"method=${c.method.fullName}\t" +
    s"source=${c.methodFullName}\tcode=${c.code}"
  )
}

val annotated = cpg.parameter
  .where(_.annotation.name("RequestParam|RequestBody|ModelAttribute|PathVariable|CookieValue"))
  .l

annotated.foreach { p =>
  println(
    s"source_candidate\tkind=request_input\tfile=${p.file.name.headOption.getOrElse("?")}\t" +
    s"line=${p.lineNumber.getOrElse(-1)}\t" +
    s"method=${p.method.fullName}\t" +
    s"source=annotation:${p.annotation.name.mkString(",")}\t" +
    s"code=${p.name}"
  )
}

val csrfTokenReads = cpg.call
  .code(".*CsrfToken.*|.*_csrf.*|.*X-CSRF-TOKEN.*|.*X-XSRF-TOKEN.*")
  .l

csrfTokenReads.foreach { c =>
  println(
    s"source_candidate\tkind=csrf_token_reference\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
    s"line=${c.lineNumber.getOrElse(-1)}\t" +
    s"method=${c.method.fullName}\tcode=${c.code}"
  )
}

println(s"total_source_candidates=${sessionCalls.size + annotated.size + csrfTokenReads.size}")
