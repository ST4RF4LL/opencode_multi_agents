/**
 * @name Java SpEL injection candidate paths
 * @description Finds flows from remote user input to SpEL parse/evaluate APIs.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/spel-injection
 * @tags security external/cwe/cwe-917 external/cwe/cwe-94
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** SpEL parseExpression sinks. */
class SpelParseSink extends DataFlow::ExprNode {
  SpelParseSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      this.asExpr() = ma.getArgument(0) and
      m.hasName("parseExpression") and
      (
        m.getDeclaringType()
            .getASupertype*()
            .hasQualifiedName("org.springframework.expression", "ExpressionParser")
        or
        m.getDeclaringType()
            .getQualifiedName()
            .matches("%SpelExpressionParser%")
      )
    )
  }
}

/** SpEL getValue/setValue evaluation sinks (receiver expression may be tainted). */
class SpelEvalSink extends DataFlow::ExprNode {
  SpelEvalSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      (
        m.hasName("getValue")
        or
        m.hasName("setValue")
      ) and
      (
        m.getDeclaringType()
            .getASupertype*()
            .hasQualifiedName("org.springframework.expression", "Expression")
        or
        m.getDeclaringType().getQualifiedName().matches("%SpelExpression%")
      ) and
      (
        this.asExpr() = ma.getQualifier()
        or
        exists(int i | i = [0 .. ma.getNumArgument() - 1] | this.asExpr() = ma.getArgument(i))
      )
    )
  }
}

class SpelInjectionConfig extends TaintTracking::Configuration {
  SpelInjectionConfig() { this = "JavaSpelInjectionSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SpelParseSink or sink instanceof SpelEvalSink
  }
}

from SpelInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SpEL operation depends on a $@.", source.getNode(), "user-controlled value"
