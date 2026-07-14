// Derived from: H1 #3292573 Django FilteredRelation injection
// Pattern: dynamic join/filter/relation fragments from user input.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val filterParamNames = Set(
    "filter", "filters", "relation", "join", "on", "predicate",
    "where", "condition", "criteria", "userData", "user_data"
  )

  val sinks = cpg.call.methodFullName(
    ".*Statement\\.execute.*|" +
    ".*prepareStatement.*|" +
    ".*JdbcTemplate\\.(query|update|execute).*|" +
    ".*createNativeQuery.*|" +
    ".*createQuery.*|" +
    ".*Criteria\\..*|" +
    ".*CriteriaBuilder\\..*"
  ).argument

  cpg.parameter.nameExact(filterParamNames.toSeq: _*).foreach { p =>
    val flows = sinks.reachableByFlows(p).l
    flows.take(30).foreach { flow =>
      println(s"pattern=dynamic-filter-fragment\tparam=${p.name}\tmethod=${p.method.fullName}")
      flow.elements.foreach { e =>
        println(s"  step\tline=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}")
      }
    }
  }

  // JOIN ... ON concat heuristics
  cpg.method.l.foreach { m =>
    val c = m.code
    val joinish = c.contains(" JOIN ") || c.contains(" join ") || c.contains(" ON ") || c.contains("\"ON\"")
    val concat = c.contains("+") || c.toLowerCase.contains("append") || c.contains("String.format")
    val sql = m.call.methodFullName(".*execute.*|.*prepareStatement.*|.*JdbcTemplate\\..*|.*createNativeQuery.*|.*createQuery.*").nonEmpty
    if (joinish && concat && sql) {
      println(
        s"pattern=dynamic-join-on\tfile=${m.filename}\tmethod=${m.fullName}"
      )
    }
  }

  println("done=dynamic-filter-fragment")
}
