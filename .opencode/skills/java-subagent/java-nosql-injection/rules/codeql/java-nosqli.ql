/**
 * @name Java NoSQL injection candidate paths
 * @description Finds flows from remote user input to MongoDB/NoSQL query APIs.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/nosql-injection
 * @tags security external/cwe/cwe-943
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** NoSQL-related sinks commonly abused for injection. */
class NoSqlSink extends DataFlow::ExprNode {
  NoSqlSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      this.asExpr() = ma.getAnArgument() and
      (
        m.hasName("parse") and
        (
          m.getDeclaringType().hasQualifiedName("org.bson", "Document")
          or
          m.getDeclaringType().hasQualifiedName("com.mongodb", "BasicDBObject")
        )
        or
        m.getDeclaringType().getASupertype*().hasQualifiedName("com.mongodb.client", "MongoCollection") and
        m.hasName(["find", "deleteOne", "deleteMany", "updateOne", "updateMany", "replaceOne", "countDocuments", "aggregate"])
        or
        m.getDeclaringType().hasQualifiedName("com.mongodb.client.model", "Filters") and
        m.hasName("where")
        or
        m.getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.data.mongodb.core", "MongoTemplate") and
        m.getName().matches(["find%", "remove%", "update%", "count%"])
        or
        m.getDeclaringType().hasQualifiedName("org.springframework.data.mongodb.core.query", "BasicQuery") and
        m.isConstructor()
        or
        m.hasName(["eval", "evalsha"]) and
        m.getDeclaringType().getQualifiedName().matches("%Jedis%")
      )
    )
  }
}

class NoSqlInjectionConfig extends TaintTracking::Configuration {
  NoSqlInjectionConfig() { this = "JavaNoSqlInjectionSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof NoSqlSink
  }
}

from NoSqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "NoSQL operation depends on a $@.", source.getNode(), "user-controlled value"
