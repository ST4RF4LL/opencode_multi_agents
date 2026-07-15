// L3 assist: find nearby path confinement / validation patterns around file sinks.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinks = cpg.call.methodFullName(
    ".*FileInputStream\\.<init>.*|" +
    ".*FileOutputStream\\.<init>.*|" +
    ".*Files\\.(readAllBytes|readString|newInputStream|newOutputStream|write|delete|copy).*|" +
    ".*Path\\.resolve.*|" +
    ".*java\\.io\\.File\\.<init>.*"
  ).l

  sinks.foreach { s =>
    val m = s.method
    val hasNormalize =
      m.call.name("normalize|getCanonicalPath|getCanonicalFile|toRealPath|toAbsolutePath").nonEmpty
    val hasStartsWith =
      m.call.name("startsWith").nonEmpty || m.code.contains("startsWith")
    val hasGetName =
      m.call.name("getName|getBaseName").nonEmpty ||
      m.code.contains("FilenameUtils.getName")
    val hasDotDotBlacklist =
      m.code.contains("..") && m.call.name("contains|replace|replaceAll|matches").nonEmpty
    val hasAllowlist =
      m.call.name("equals|contains|valueOf|fromValue").nonEmpty &&
      (m.code.contains("allow") || m.code.contains("ALLOWED") || m.code.contains("whitelist"))
    val hasZipEntry =
      m.call.methodFullName(".*ZipEntry\\.getName.*|.*JarEntry\\.getName.*").nonEmpty
    val hasOriginalFilename =
      m.call.methodFullName(".*getOriginalFilename.*|.*getSubmittedFileName.*").nonEmpty

    println(
      s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
      s"line=${s.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"has_normalize=$hasNormalize\t" +
      s"has_startswith=$hasStartsWith\t" +
      s"has_filename_utils_getname=$hasGetName\t" +
      s"has_dotdot_blacklist=$hasDotDotBlacklist\t" +
      s"has_allowlist_like=$hasAllowlist\t" +
      s"has_zip_entry_name=$hasZipEntry\t" +
      s"has_original_filename=$hasOriginalFilename\t" +
      s"sink=${s.methodFullName}"
    )
  }
}
