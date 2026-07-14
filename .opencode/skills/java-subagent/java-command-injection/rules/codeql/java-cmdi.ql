/**
 * @name Java OS command injection candidate paths
 * @description Finds flows from remote user input to OS command execution APIs.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/command-injection
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** OS command-related sinks commonly abused for injection. */
class CommandSink extends DataFlow::ExprNode {
  CommandSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      (
        m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
        m.hasName("exec") and
        this.asExpr() = ma.getArgument(0)
        or
        m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
        m.hasName(["command"]) and
        this.asExpr() = ma.getAnArgument()
        or
        m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
        m.isConstructor() and
        this.asExpr() = ma.getAnArgument()
        or
        m.getDeclaringType().getASupertype*().hasQualifiedName("org.apache.commons.exec", "Executor") and
        m.hasName("execute") and
        this.asExpr() = ma.getArgument(0)
        or
        m.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "CommandLine") and
        m.hasName(["parse", "addArguments"]) and
        this.asExpr() = ma.getArgument(0)
      )
    )
  }
}

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "JavaCommandInjectionSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandSink
  }
}

from CommandInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "OS command operation depends on a $@.", source.getNode(), "user-controlled value"
