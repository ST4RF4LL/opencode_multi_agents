// L3 assist: find nearby validation / construction patterns around command sinks.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinks = cpg.call.methodFullName(
    ".*Runtime\\.exec.*|" +
    ".*ProcessBuilder\\.<init>.*|" +
    ".*ProcessBuilder\\.command.*|" +
    ".*ProcessBuilder\\.start.*|" +
    ".*DefaultExecutor\\.execute.*|" +
    ".*CommandLine\\.parse.*"
  ).l

  sinks.foreach { s =>
    val m = s.method
    val hasAllowlist = m.call.name("contains|equals|valueOf|fromValue|matches").nonEmpty
    val hasReplace = m.call.name("replace|replaceAll|quote|escape").nonEmpty
    val hasConcat = m.call.name("concat|format|append").nonEmpty || m.code.contains("+")
    val hasShellHint =
      m.code.contains("/bin/sh") ||
      m.code.contains("cmd.exe") ||
      m.code.contains("\"-c\"") ||
      m.code.contains("'/c'") ||
      m.code.contains("\"/c\"")
    val hasProcessBuilderList =
      m.code.contains("ProcessBuilder") && !hasShellHint

    println(
      s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
      s"line=${s.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"has_allowlist_like=$hasAllowlist\t" +
      s"has_escape_replace=$hasReplace\t" +
      s"has_concat_hint=$hasConcat\t" +
      s"has_shell_wrapper_hint=$hasShellHint\t" +
      s"has_processbuilder_list_hint=$hasProcessBuilderList\t" +
      s"sink=${s.methodFullName}"
    )
  }
}
