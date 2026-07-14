/**
 * @name Java SQL injection candidate paths
 * @description Finds flows from remote user input to SQL execution APIs.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/sql-injection
 * @tags security external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** SQL-related sinks commonly abused for injection. */
class SqlSink extends DataFlow::ExprNode {
  SqlSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      this.asExpr() = ma.getArgument(0) and
      (
        m.getDeclaringType().hasQualifiedName("java.sql", "Statement") and
        m.hasName(["execute", "executeQuery", "executeUpdate", "addBatch"])
        or
        m.getDeclaringType().hasQualifiedName("java.sql", "Connection") and
        m.hasName(["prepareStatement", "prepareCall"])
        or
        m.getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
        m.getName().matches(["query%", "update%", "execute%"])
        or
        m.hasName(["createNativeQuery", "createQuery", "createSQLQuery"]) and
        (
          m.getDeclaringType().getASupertype*().hasQualifiedName("javax.persistence", "EntityManager")
          or
          m.getDeclaringType().getASupertype*().hasQualifiedName("jakarta.persistence", "EntityManager")
          or
          m.getDeclaringType().getQualifiedName().matches("%Session%")
        )
      )
    )
  }
}

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "JavaSqlInjectionSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlSink
  }
}

from SqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL operation depends on a $@.", source.getNode(), "user-controlled value"