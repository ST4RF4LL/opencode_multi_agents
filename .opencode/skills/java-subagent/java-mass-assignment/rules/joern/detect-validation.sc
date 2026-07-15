// L3 assist: find field-control patterns around mass-assignment binding sites.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val binders = cpg.method
    .where(_.annotation.name("InitBinder"))
    .l

  binders.foreach { m =>
    val hasAllowed = m.call.name("setAllowedFields").nonEmpty || m.code.contains("setAllowedFields")
    val hasDisallowed = m.call.name("setDisallowedFields").nonEmpty || m.code.contains("setDisallowedFields")
    println(
      s"initbinder\tfile=${m.filename}\tline=${m.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"has_allowed_fields=$hasAllowed\t" +
      s"has_disallowed_fields=$hasDisallowed"
    )
  }

  val jsonIgnore = cpg.annotation.name("JsonIgnore|JsonIgnoreProperties").l
  jsonIgnore.foreach { a =>
    println(
      s"json_control\tname=${a.name}\t" +
      s"file=${a.file.name.headOption.getOrElse("?")}\t" +
      s"line=${a.lineNumber.getOrElse(-1)}\t" +
      s"code=${a.code}"
    )
  }

  val readOnly = cpg.annotation
    .filter(a => a.code.contains("READ_ONLY") || a.code.contains("Access.READ_ONLY"))
    .l
  readOnly.foreach { a =>
    println(
      s"json_readonly\tfile=${a.file.name.headOption.getOrElse("?")}\t" +
      s"line=${a.lineNumber.getOrElse(-1)}\tcode=${a.code}"
    )
  }

  val copies = cpg.call.methodFullName(".*BeanUtils\\.copyProperties.*|.*PropertyUtils\\.copyProperties.*").l
  copies.foreach { c =>
    val m = c.method
    val hasIgnoreArg = c.argument.size > 2
    println(
      s"bean_copy\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
      s"line=${c.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"has_extra_ignore_args=$hasIgnoreArg\t" +
      s"code=${c.code}"
    )
  }

  val boundParams = cpg.parameter
    .where(_.annotation.name("RequestBody|ModelAttribute"))
    .l

  boundParams.foreach { p =>
    val typeName = p.typeFullName
    val sensitiveOnType = cpg.typeDecl.fullNameExact(typeName)
      .method
      .name("setAdmin|setRole|setRoles|setBalance|setOwnerId|setAuthorities|setVerified")
      .nonEmpty
    println(
      s"binding_sensitivity\tmethod=${p.method.fullName}\t" +
      s"param=${p.name}\ttype=$typeName\t" +
      s"has_sensitive_setters=$sensitiveOnType"
    )
  }
}
