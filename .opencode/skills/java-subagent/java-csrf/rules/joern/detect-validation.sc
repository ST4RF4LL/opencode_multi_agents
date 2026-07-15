// L3 assist: find CSRF controls near security config and mutating handlers.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  // Security config methods
  val securityMethods = cpg.method
    .where(_.name(".*filterChain.*|.*configure.*|.*securityFilterChain.*"))
    .l

  securityMethods.foreach { m =>
    val code = m.code
    val hasCsrfDisable = code.matches("(?s).*csrf.*disable.*")
    val hasCsrfTokenRepo = code.contains("CsrfToken") || code.contains("csrfTokenRepository")
    val hasIgnoring = code.contains("ignoringRequestMatchers") || code.contains("ignoringAntMatchers")
    val hasCookieRepo = code.contains("CookieCsrfTokenRepository")
    println(
      s"control_context\tkind=security_config\tfile=${m.filename}\t" +
      s"line=${m.lineNumber.getOrElse(-1)}\tmethod=${m.fullName}\t" +
      s"csrf_disable=$hasCsrfDisable\t" +
      s"csrf_token_repo=$hasCsrfTokenRepo\t" +
      s"cookie_csrf_repo=$hasCookieRepo\t" +
      s"csrf_ignoring=$hasIgnoring"
    )
  }

  // Mutating handlers: look for token/header/origin checks in method body
  val mutating = cpg.annotation
    .name("PostMapping|PutMapping|DeleteMapping|PatchMapping|GetMapping")
    .method
    .l
    .distinct

  mutating.foreach { m =>
    val code = m.code
    val hasCsrfParam = code.contains("_csrf") || code.contains("CsrfToken") ||
      code.contains("X-CSRF") || code.contains("X-XSRF")
    val hasOrigin = code.contains("Origin") || code.contains("Referer")
    val hasCustomHeader = code.contains("getHeader") && (
      code.contains("X-Requested-With") || code.contains("CSRF") || code.contains("X-")
    )
    val hasSession = code.contains("getSession") || code.contains("SecurityContext")
    val hasStateWrite =
      m.call.methodFullName(".*delete.*|.*save.*|.*update.*|.*setAttribute.*").nonEmpty

    println(
      s"control_context\tkind=handler\tfile=${m.filename}\t" +
      s"line=${m.lineNumber.getOrElse(-1)}\tmethod=${m.fullName}\t" +
      s"has_csrf_token_ref=$hasCsrfParam\t" +
      s"has_origin_referer=$hasOrigin\t" +
      s"has_custom_header_check=$hasCustomHeader\t" +
      s"uses_session=$hasSession\t" +
      s"has_state_write_hint=$hasStateWrite"
    )
  }
}
