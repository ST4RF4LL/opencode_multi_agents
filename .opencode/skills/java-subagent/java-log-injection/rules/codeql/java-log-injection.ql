/**
 * @name Java log injection candidate paths
 * @description Finds flows from remote user input to logging APIs.
 * @kind path-problem
 * @problem.severity warning
 * @id java/skill/log-injection
 * @tags security external/cwe/cwe-117 external/cwe/cwe-093
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** Logging sinks commonly abused for log forging. */
class LogSink extends DataFlow::ExprNode {
  LogSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      this.asExpr() = ma.getAnArgument() and
      (
        m.getDeclaringType().getASupertype*().hasQualifiedName("org.slf4j", "Logger") and
        m.hasName(["trace", "debug", "info", "warn", "error"])
        or
        m.getDeclaringType().getASupertype*().hasQualifiedName("org.apache.logging.log4j", "Logger") and
        m.hasName(["trace", "debug", "info", "warn", "error", "fatal", "log", "printf"])
        or
        m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
        m.hasName(["log", "severe", "warning", "info", "fine", "finer", "finest"])
        or
        m.getDeclaringType().getASupertype*().hasQualifiedName("org.apache.commons.logging", "Log") and
        m.hasName(["trace", "debug", "info", "warn", "error", "fatal"])
        or
        m.getDeclaringType().hasQualifiedName("org.slf4j", "MDC") and
        m.hasName("put")
        or
        m.getDeclaringType().hasQualifiedName("org.apache.logging.log4j", "ThreadContext") and
        m.hasName(["put", "push"])
      )
    )
  }
}

class LogInjectionConfig extends TaintTracking::Configuration {
  LogInjectionConfig() { this = "JavaLogInjectionSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof LogSink
  }
}

from LogInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Log operation depends on a $@.", source.getNode(), "user-controlled value"
