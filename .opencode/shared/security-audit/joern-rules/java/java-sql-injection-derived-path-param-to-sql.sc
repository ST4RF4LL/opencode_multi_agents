// Derived from: H1 #2958619 / #2633959 / #2266081 (URL path SQLi)
// Pattern: path variables / pathInfo flow into SQL construction.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val pathSources = cpg.call.methodFullName(
  ".*HttpServletRequest\\.getPathInfo.*|" +
  ".*HttpServletRequest\\.getRequestURI.*|" +
  ".*HttpServletRequest\\.getServletPath.*"
).argument ++
  cpg.parameter.where(_.annotation.name("PathVariable")).l

val sinks = cpg.call.methodFullName(
  ".*Statement\\.execute.*|" +
  ".*Statement\\.executeQuery.*|" +
  ".*Statement\\.executeUpdate.*|" +
  ".*Connection\\.prepareStatement.*|" +
  ".*JdbcTemplate\\.(query|update|execute).*|" +
  ".*EntityManager\\.createNativeQuery.*|" +
  ".*EntityManager\\.createQuery.*|" +
  ".*Session\\.create(SQL|Native)?Query.*"
).argument(1)

val flows = sinks.reachableByFlows(pathSources).l
flows.zipWithIndex.foreach { case (flow, idx) =>
  println(s"pattern=path-param-to-sql\tid=PATH-SQL-$idx")
  flow.elements.foreach { e =>
    println(
      s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
      s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
    )
  }
}

// Annotation-based PathVariable by common id names even without flow engine hits
cpg.parameter
  .where(_.annotation.name("PathVariable"))
  .name("(?i).*id.*|.*code.*|.*customer.*|.*org.*")
  .foreach { p =>
    val localFlows = sinks.reachableByFlows(p).l
    if (localFlows.nonEmpty) {
      println(s"pattern=path-param-to-sql-named\tparam=${p.name}\tmethod=${p.method.fullName}\tflows=${localFlows.size}")
    } else {
      // still surface as review candidate if method also contains SQL sinks
      if (p.method.call.methodFullName(".*executeQuery.*|.*prepareStatement.*|.*JdbcTemplate\\..*|.*createNativeQuery.*").nonEmpty) {
        println(
          s"pattern=path-param-sql-adjacent\t" +
          s"param=${p.name}\tmethod=${p.method.fullName}\t" +
          s"note=path_param_in_method_with_sql_sink_review_concat"
        )
      }
    }
  }

println(s"total_path_sql_flows=${flows.size}")
println("done=path-param-to-sql")
