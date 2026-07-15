// L3 assist: find nearby type policy / storage patterns around upload sinks.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinks = cpg.call.methodFullName(
    ".*MultipartFile\\.transferTo.*|" +
    ".*Part\\.write.*|" +
    ".*FileItem\\.write.*|" +
    ".*Files\\.(copy|write|newOutputStream).*|" +
    ".*FileOutputStream\\.<init>.*"
  ).l

  sinks.foreach { s =>
    val m = s.method
    val hasContentTypeCheck =
      m.call.methodFullName(".*getContentType.*").nonEmpty ||
      m.code.contains("getContentType") ||
      m.code.contains("image/")
    val hasExtensionCheck =
      m.code.contains("getExtension") ||
      m.code.contains("endsWith") ||
      m.code.contains("lastIndexOf('.')") ||
      m.code.contains("lastIndexOf(\".\")")
    val hasAllowlist =
      (m.code.contains("allow") || m.code.contains("ALLOWED") || m.code.contains("whitelist") ||
        m.code.contains("Set.of") || m.code.contains("Arrays.asList")) &&
      (m.call.name("contains|equals|containsKey").nonEmpty || m.code.contains("contains"))
    val hasBlacklist =
      m.code.contains(".jsp") || m.code.contains("blacklist") || m.code.contains("forbidden")
    val hasUuidRename =
      m.code.contains("UUID") || m.code.contains("randomUUID") || m.code.contains("UUID.randomUUID")
    val hasRealPath =
      m.call.methodFullName(".*getRealPath.*").nonEmpty || m.code.contains("getRealPath")
    val hasOriginalFilename =
      m.call.methodFullName(".*getOriginalFilename.*|.*getSubmittedFileName.*|.*FileItem\\.getName.*").nonEmpty
    val hasMagicOrImageIO =
      m.code.contains("ImageIO") || m.code.contains("magic") || m.code.contains("Tika") ||
      m.code.contains("probeContentType")

    println(
      s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
      s"line=${s.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"has_content_type_check=$hasContentTypeCheck\t" +
      s"has_extension_check=$hasExtensionCheck\t" +
      s"has_allowlist_like=$hasAllowlist\t" +
      s"has_blacklist_like=$hasBlacklist\t" +
      s"has_uuid_rename=$hasUuidRename\t" +
      s"has_realpath_webroot=$hasRealPath\t" +
      s"has_original_filename=$hasOriginalFilename\t" +
      s"has_magic_or_imageio=$hasMagicOrImageIO\t" +
      s"sink=${s.methodFullName}"
    )
  }
}
