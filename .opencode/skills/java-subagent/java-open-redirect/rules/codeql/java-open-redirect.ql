/**
 * @name Java open redirect candidate paths
 * @description Finds flows from remote user input to browser redirect APIs.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/open-redirect
 * @tags security external/cwe/cwe-601
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** Common browser-redirect sinks for open-redirect analysis. */
class OpenRedirectSink extends DataFlow::ExprNode {
  OpenRedirectSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      (
        m.hasName("sendRedirect") and
        m.getDeclaringType().getASupertype*().hasQualifiedName(["javax.servlet.http", "jakarta.servlet.http"], "HttpServletResponse") and
        this.asExpr() = ma.getArgument(0)
        or
        (
          m.hasName("setHeader") or
          m.hasName("addHeader")
        ) and
        m.getDeclaringType().getASupertype*().hasQualifiedName(["javax.servlet.http", "jakarta.servlet.http"], "HttpServletResponse") and
        ma.getArgument(0).(CompileTimeConstantExpr).getStringValue().toLowerCase() = "location" and
        this.asExpr() = ma.getArgument(1)
        or
        m.hasName("setUrl") and
        m.getDeclaringType().getQualifiedName().matches("%RedirectView%") and
        this.asExpr() = ma.getArgument(0)
        or
        m.hasName("setLocation") and
        m.getDeclaringType().getQualifiedName().matches("%HttpHeaders%") and
        this.asExpr() = ma.getArgument(0)
        or
        m.hasName("location") and
        m.getDeclaringType().getQualifiedName().matches("%ResponseEntity%") and
        this.asExpr() = ma.getArgument(0)
        or
        m.hasName("setViewName") and
        m.getDeclaringType().getQualifiedName().matches("%ModelAndView%") and
        this.asExpr() = ma.getArgument(0)
      )
    )
    or
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().getName() = "RedirectView" and
      this.asExpr() = cie.getArgument(0)
    )
  }
}

class OpenRedirectConfig extends TaintTracking::Configuration {
  OpenRedirectConfig() { this = "JavaOpenRedirectSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof OpenRedirectSink
  }
}

from OpenRedirectConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Browser redirect depends on a $@.", source.getNode(), "user-controlled value"
