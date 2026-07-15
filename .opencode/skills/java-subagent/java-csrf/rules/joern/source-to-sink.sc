// L2: connect cookie/session auth and request inputs to state-changing handlers.
// CSRF is not classic string taint SSRF-style; model auth + mutation reachability.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sessionSources = cpg.call.methodFullName(
    ".*HttpServletRequest\\.getSession.*|" +
    ".*HttpSession\\.getAttribute.*|" +
    ".*SecurityContextHolder\\.getContext.*"
  )

  val requestParams = cpg.parameter
    .where(_.annotation.name("RequestParam|RequestBody|ModelAttribute|PathVariable"))

  val stateSinks = cpg.call.methodFullName(
    ".*Repository\\.(save|delete|deleteById).*|" +
    ".*JdbcTemplate\\.(update|batchUpdate).*|" +
    ".*EntityManager\\.(persist|merge|remove).*|" +
    ".*HttpSession\\.(setAttribute|invalidate).*|" +
    ".*PasswordEncoder\\.encode.*|" +
    ".*changePassword.*|.*updatePassword.*"
  )

  val flowsSession = stateSinks.reachableByFlows(sessionSources.argument).l
  val flowsParams = stateSinks.reachableByFlows(requestParams).l
  val flows = flowsSession ++ flowsParams

  flows.zipWithIndex.foreach { case (flow, idx) =>
    println(s"dataflow_id=CSRF-FLOW-$idx")
    flow.elements.foreach { e =>
      println(
        s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
        s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
      )
    }
  }

  // Pair CSRF disable config with mutating controllers in same project (heuristic)
  val disableCount = cpg.call.code(".*csrf.*disable.*").size
  val mutatingControllers = cpg.annotation
    .name("PostMapping|PutMapping|DeleteMapping|PatchMapping")
    .method
    .fullName
    .l
    .distinct

  println(s"csrf_disable_hits=$disableCount")
  mutatingControllers.foreach { m =>
    println(s"mutating_handler=$m")
  }
  println(s"total_flows=${flows.size}")
}
