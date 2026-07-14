/**
 * @name Java XPath injection candidate paths
 * @description Finds flows from remote user input to XPath compile/evaluate APIs.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/xpath-injection
 * @tags security external/cwe/cwe-643
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** XPath-related sinks commonly abused for injection. */
class XPathSink extends DataFlow::ExprNode {
  XPathSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      this.asExpr() = ma.getArgument(0) and
      (
        m.hasName("compile") and
        (
          m.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.xpath", "XPath")
          or
          m.getDeclaringType().getASupertype*().hasQualifiedName("jakarta.xml.xpath", "XPath")
          or
          m.getDeclaringType().getQualifiedName().matches("%XPathCompiler%")
          or
          m.getDeclaringType().getQualifiedName().matches("%XPathEvaluator%")
        )
        or
        m.hasName("evaluate") and
        (
          m.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.xpath", "XPath")
          or
          m.getDeclaringType().getASupertype*().hasQualifiedName("jakarta.xml.xpath", "XPath")
          or
          m.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.xpath", "XPathExpression")
          or
          m.getDeclaringType().getASupertype*().hasQualifiedName("jakarta.xml.xpath", "XPathExpression")
          or
          m.getDeclaringType().getQualifiedName().matches("%XPathEvaluator%")
        ) and
        ma.getArgument(0).getType() instanceof TypeString
      )
    )
  }
}

class XPathInjectionConfig extends TaintTracking::Configuration {
  XPathInjectionConfig() { this = "JavaXPathInjectionSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof XPathSink
  }
}

from XPathInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "XPath operation depends on a $@.", source.getNode(), "user-controlled value"
