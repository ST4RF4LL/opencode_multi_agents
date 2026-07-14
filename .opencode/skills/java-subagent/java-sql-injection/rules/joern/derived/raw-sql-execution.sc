// Derived from: CVE-2024-12909 / GHSA-x48g-hm9c-ww42 (llama-index run_sql_query)
// Pattern: entire SQL string is external/agent-controlled and executed.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinks = cpg.call.methodFullName(
    ".*Statement\\.execute.*|" +
    ".*Statement\\.executeQuery.*|" +
    ".*Statement\\.executeUpdate.*|" +
    ".*JdbcTemplate\\.execute.*|" +
    ".*JdbcTemplate\\.query.*|" +
    ".*JdbcTemplate\\.update.*|" +
    ".*EntityManager\\.createNativeQuery.*|" +
    ".*Session\\.createSQLQuery.*|" +
    ".*Session\\.createNativeQuery.*"
  ).l

  // Parameter names suggesting full SQL body
  val sqlParamNames = Set("sql", "query", "rawSql", "rawQuery", "statement", "userSql", "customSql")

  cpg.parameter.nameExact(sqlParamNames.toSeq: _*).foreach { p =>
    val flows = sinks.argument.reachableByFlows(p).l
    flows.foreach { flow =>
      println(s"pattern=raw-sql-execution\tparam=${p.name}\tmethod=${p.method.fullName}")
      flow.elements.foreach { e =>
        println(s"  step\tline=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}")
      }
    }
  }

  // Methods named like runSql/executeSql/queryRaw with non-literal first arg
  val runnerMethods = cpg.method.name("(?i).*(run|exec).*sql.*|.*rawQuery.*|.*executeQuery.*").l
  runnerMethods.foreach { m =>
    val calls = m.call.methodFullName(".*Statement\\.execute.*|.*JdbcTemplate\\..*|.*createNativeQuery.*").l
    calls.foreach { c =>
      val arg0 = c.argument.headOption.map(_.code).getOrElse("")
      val literal = arg0.startsWith("\"") || arg0.startsWith("'")
      if (!literal) {
        println(
          s"pattern=raw-sql-execution-runner\t" +
          s"file=${c.file.name.headOption.getOrElse("?")}\t" +
          s"line=${c.lineNumber.getOrElse(-1)}\t" +
          s"method=${m.fullName}\tcode=${c.code}"
        )
      }
    }
  }

  println("done=raw-sql-execution")
}
