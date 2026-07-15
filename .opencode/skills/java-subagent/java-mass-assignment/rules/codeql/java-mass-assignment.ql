/**
 * @name Java mass assignment candidate paths
 * @description Finds request-bound objects flowing into persistence or bulk property copy APIs.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/mass-assignment
 * @tags security external/cwe/cwe-915
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** Parameters bound from HTTP request body or form model attributes. */
class BoundRequestParam extends DataFlow::Node {
  BoundRequestParam() {
    exists(Parameter p, Annotation ann |
      this.asParameter() = p and
      ann = p.getAnAnnotation() and
      (
        ann.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody") or
        ann.getType().hasQualifiedName("org.springframework.web.bind.annotation", "ModelAttribute") or
        ann.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestPart")
      )
    )
  }
}

/** Persistence and bulk-transfer sinks that materialize over-posting. */
class MassAssignmentSink extends DataFlow::ExprNode {
  MassAssignmentSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      (
        (
          m.hasName("save") or
          m.hasName("saveAndFlush") or
          m.hasName("saveAll")
        ) and
        (
          m.getDeclaringType().getASupertype*().getSourceDeclaration().getName().matches("%Repository%") or
          m.getDeclaringType().getASupertype*().getSourceDeclaration().getName().matches("%CrudRepository%")
        ) and
        this.asExpr() = ma.getArgument(0)
        or
        (
          m.hasName("persist") or
          m.hasName("merge")
        ) and
        m.getDeclaringType().hasQualifiedName("javax.persistence", "EntityManager") and
        this.asExpr() = ma.getArgument(0)
        or
        (
          m.hasName("persist") or
          m.hasName("merge")
        ) and
        m.getDeclaringType().hasQualifiedName("jakarta.persistence", "EntityManager") and
        this.asExpr() = ma.getArgument(0)
        or
        m.hasName("copyProperties") and
        m.getDeclaringType().getName().matches("%BeanUtils%") and
        this.asExpr() = ma.getAnArgument()
        or
        (
          m.hasName("readerForUpdating") or
          m.hasName("updateValue") or
          m.hasName("readValue")
        ) and
        m.getDeclaringType().getASupertype*().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper") and
        this.asExpr() = ma.getAnArgument()
      )
    )
  }
}

class MassAssignmentConfig extends TaintTracking::Configuration {
  MassAssignmentConfig() { this = "JavaMassAssignmentSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof BoundRequestParam or
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MassAssignmentSink
  }
}

from MassAssignmentConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Possible mass assignment: request-bound value reaches $@.", sink.getNode(),
  "persistence or bulk property transfer"
