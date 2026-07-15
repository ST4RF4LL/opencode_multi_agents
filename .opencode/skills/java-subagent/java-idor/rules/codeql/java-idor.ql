/**
 * @name Java IDOR / BOLA candidate paths
 * @description Finds flows from remote user input (object ids) to resource load/delete APIs.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/idor
 * @tags security external/cwe/cwe-639 external/cwe/cwe-862
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** Common resource access sinks for IDOR analysis. */
class IdorSink extends DataFlow::ExprNode {
  IdorSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      (
        (
          m.hasName("findById") or
          m.hasName("getOne") or
          m.hasName("getById") or
          m.hasName("getReferenceById") or
          m.hasName("deleteById")
        ) and
        (
          m.getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.data.repository", "CrudRepository") or
          m.getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.data.jpa.repository", "JpaRepository") or
          m.getDeclaringType().getName().matches("%Repository")
        ) and
        this.asExpr() = ma.getArgument(0)
        or
        (
          m.hasName("find") or
          m.hasName("getReference") or
          m.hasName("remove") or
          m.hasName("merge")
        ) and
        m.getDeclaringType().hasQualifiedName(["javax.persistence", "jakarta.persistence"], "EntityManager") and
        (
          this.asExpr() = ma.getArgument(0) or
          this.asExpr() = ma.getArgument(1)
        )
        or
        (
          m.hasName("selectByPrimaryKey") or
          m.hasName("selectById") or
          m.hasName("deleteByPrimaryKey") or
          m.hasName("updateByPrimaryKey")
        ) and
        m.getDeclaringType().getName().matches("%Mapper") and
        this.asExpr() = ma.getArgument(0)
      )
    )
  }
}

class IdorConfig extends TaintTracking::Configuration {
  IdorConfig() { this = "JavaIdorSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof IdorSink
  }
}

from IdorConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Resource access depends on a $@ without proving object-level authorization.", source.getNode(),
  "user-controlled object identifier"
