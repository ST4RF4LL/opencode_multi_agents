// Derived from: CVE-2026-26198 / GHSA-xxh2-68g9-8jqr (ormar aggregate column injection)
// Pattern: untrusted identifier (column/sort/table) concatenated into SQL structure.
// Output: SinkCandidate / DataflowCandidate — not a final finding.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  // Calls that often carry ORDER BY / column fragments
  val sqlSinks = cpg.call.methodFullName(
    ".*Statement\\.execute.*|" +
    ".*Statement\\.executeQuery.*|" +
    ".*Connection\\.prepareStatement.*|" +
    ".*JdbcTemplate\\.(query|update|execute).*|" +
    ".*EntityManager\\.createNativeQuery.*|" +
    ".*EntityManager\\.createQuery.*|" +
    ".*Session\\.create(SQL|Native)?Query.*"
  ).l

  // Heuristic: SQL arg built with concat/format/append near identifier keywords
  val idKeywords = List("ORDER BY", "order by", "GROUP BY", "group by", "SELECT ", "FROM ")

  sqlSinks.foreach { sink =>
    val arg = sink.argument.headOption
    val m = sink.method
    val methodCode = m.code.toLowerCase
    val hasConcat =
      m.call.name("concat|format|append").nonEmpty ||
      m.code.contains("+") ||
      methodCode.contains("stringbuilder") ||
      methodCode.contains("string.format")
    val hasIdKeyword = idKeywords.exists(k => m.code.contains(k) || sink.code.contains(k))

    if (hasConcat && hasIdKeyword) {
      println(
        s"pattern=dynamic-identifier\t" +
        s"file=${sink.file.name.headOption.getOrElse("?")}\t" +
        s"line=${sink.lineNumber.getOrElse(-1)}\t" +
        s"method=${m.fullName}\t" +
        s"sink=${sink.methodFullName}\t" +
        s"code=${sink.code}"
      )
    }
  }

  // Also flag parameters named like sort/order/column/field flowing to sinks
  val idParamNames = Set("sort", "order", "orderby", "orderBy", "column", "col", "field", "table", "sortBy", "sortField")
  val sources = cpg.parameter.nameExact(idParamNames.toSeq: _*).l ++
    cpg.call.methodFullName(".*getParameter.*").l

  val sinkArgs = cpg.call.methodFullName(
    ".*Statement\\.execute.*|" +
    ".*prepareStatement.*|" +
    ".*JdbcTemplate\\.(query|update|execute).*|" +
    ".*createNativeQuery.*|" +
    ".*createQuery.*"
  ).argument

  // Parameter-name based sources
  cpg.parameter.nameExact(idParamNames.toSeq: _*).foreach { p =>
    val flows = sinkArgs.reachableByFlows(p).l
    flows.take(20).foreach { flow =>
      println(s"pattern=dynamic-identifier-flow\tparam=${p.name}\tsteps=${flow.elements.size}")
      flow.elements.foreach { e =>
        println(s"  step\tline=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}")
      }
    }
  }

  println("done=dynamic-identifier")
}
