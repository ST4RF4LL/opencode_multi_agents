// L2: source-to-sink dataflow for IDOR candidates (object id -> resource access).
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sourceCalls = cpg.call.methodFullName(
    ".*HttpServletRequest\\.getParameter.*|" +
    ".*HttpServletRequest\\.getHeader.*|" +
    ".*HttpServletRequest\\.getPathInfo.*"
  ).argument

  val annotatedSources = cpg.parameter
    .where(_.annotation.name("PathVariable|RequestParam|RequestHeader|RequestBody|ModelAttribute"))

  val sinks = cpg.call.methodFullName(
    ".*JpaRepository\\.findById.*|" +
    ".*CrudRepository\\.findById.*|" +
    ".*Repository\\.findById.*|" +
    ".*JpaRepository\\.getOne.*|" +
    ".*JpaRepository\\.getById.*|" +
    ".*JpaRepository\\.getReferenceById.*|" +
    ".*JpaRepository\\.deleteById.*|" +
    ".*CrudRepository\\.deleteById.*|" +
    ".*JpaRepository\\.delete.*|" +
    ".*JpaRepository\\.save.*|" +
    ".*EntityManager\\.find.*|" +
    ".*EntityManager\\.remove.*|" +
    ".*EntityManager\\.merge.*|" +
    ".*Mapper\\.selectByPrimaryKey.*|" +
    ".*Mapper\\.deleteByPrimaryKey.*|" +
    ".*Mapper\\.updateByPrimaryKey.*"
  ).argument

  val allSinks = sinks

  val flowsFromCalls = allSinks.reachableByFlows(sourceCalls).l
  val flowsFromParams = allSinks.reachableByFlows(annotatedSources).l
  val flows = flowsFromCalls ++ flowsFromParams

  flows.zipWithIndex.foreach { case (flow, idx) =>
    println(s"dataflow_id=IDOR-FLOW-$idx")
    flow.elements.foreach { e =>
      println(
        s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
        s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
      )
    }
  }

  println(s"total_flows=${flows.size}")
}
