// L1: locate mass-assignment binding and persistence sinks. Output SinkCandidate, not findings.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val savePattern =
    ".*CrudRepository\\.save.*|" +
    ".*JpaRepository\\.save.*|" +
    ".*JpaRepository\\.saveAndFlush.*|" +
    ".*EntityManager\\.(persist|merge).*|" +
    ".*BeanUtils\\.copyProperties.*|" +
    ".*PropertyUtils\\.copyProperties.*|" +
    ".*ObjectMapper\\.readerForUpdating.*|" +
    ".*ObjectMapper\\.updateValue.*|" +
    ".*ObjectMapper\\.readValue.*|" +
    ".*JsonPatch\\.apply.*|" +
    ".*JsonMergePatch\\.apply.*"

  val sinks = cpg.call.methodFullName(savePattern).l

  sinks.foreach { c =>
    println(
      s"sink_candidate\tfile=${c.file.name.headOption.getOrElse("?")}\t" +
      s"line=${c.lineNumber.getOrElse(-1)}\t" +
      s"method=${c.method.fullName}\t" +
      s"sink=${c.methodFullName}\t" +
      s"code=${c.code}"
    )
  }

  val boundParams = cpg.parameter
    .where(_.annotation.name("ModelAttribute|RequestBody|RequestPart"))
    .l

  boundParams.foreach { p =>
    println(
      s"binding_candidate\tfile=${p.file.name.headOption.getOrElse("?")}\t" +
      s"line=${p.lineNumber.getOrElse(-1)}\t" +
      s"method=${p.method.fullName}\t" +
      s"annotation=${p.annotation.name.mkString(",")}\t" +
      s"type=${p.typeFullName}\t" +
      s"name=${p.name}"
    )
  }

  println(s"total_sink_candidates=${sinks.size}")
  println(s"total_binding_candidates=${boundParams.size}")
}
