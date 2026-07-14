// Derived from: H1 #3335709 Django Q object _connector injection
// Pattern: logical operators / connectors from user interpolated into SQL/HQL.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val opParamNames = Set(
    "op", "operator", "connector", "logic", "combinator",
    "andOr", "boolOp", "conditionOp", "filterOp"
  )

  val sinks = cpg.call.methodFullName(
    ".*Statement\\.execute.*|" +
    ".*prepareStatement.*|" +
    ".*JdbcTemplate\\.(query|update|execute).*|" +
    ".*createNativeQuery.*|" +
    ".*createQuery.*"
  ).argument

  cpg.parameter.nameExact(opParamNames.toSeq: _*).foreach { p =>
    val flows = sinks.reachableByFlows(p).l
    flows.foreach { flow =>
      println(s"pattern=operator-connector-inject\tparam=${p.name}\tmethod=${p.method.fullName}")
      flow.elements.foreach { e =>
        println(s"  step\tline=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}")
      }
    }
  }

  // String fragments containing AND/OR concatenation patterns in methods with SQL sinks
  cpg.method.l.foreach { m =>
    val code = m.code
    val hasOpConcat =
      (code.contains("+") || code.toLowerCase.contains("append")) &&
      (code.contains(" AND ") || code.contains(" OR ") || code.contains("\"AND\"") || code.contains("\"OR\""))
    val hasSqlSink = m.call.methodFullName(
      ".*executeQuery.*|.*prepareStatement.*|.*JdbcTemplate\\..*|.*createNativeQuery.*|.*createQuery.*"
    ).nonEmpty
    if (hasOpConcat && hasSqlSink) {
      println(
        s"pattern=operator-connector-concat\t" +
        s"file=${m.filename}\tmethod=${m.fullName}\t" +
        s"note=review_operator_allowlist"
      )
    }
  }

  println("done=operator-connector-inject")
}
