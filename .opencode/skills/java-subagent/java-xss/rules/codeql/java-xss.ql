/**
 * @name Java XSS candidate paths
 * @description Finds flows from remote user input to HTTP response writers and similar sinks.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/xss
 * @tags security external/cwe/cwe-079
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** Common server-side XSS sinks. */
class XssSink extends DataFlow::ExprNode {
  XssSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      this.asExpr() = ma.getAnArgument() and
      (
        m.getDeclaringType().hasQualifiedName("java.io", "PrintWriter") and
        m.hasName(["print", "println", "write", "append", "format", "printf"])
        or
        m.getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet", "ServletOutputStream") and
        m.hasName(["print", "println", "write"])
        or
        m.getDeclaringType().getASupertype*().hasQualifiedName("jakarta.servlet", "ServletOutputStream") and
        m.hasName(["print", "println", "write"])
        or
        m.getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
        m.hasName("sendError") and
        ma.getNumArgument() = 2 and
        this.asExpr() = ma.getArgument(1)
        or
        m.getDeclaringType().getASupertype*().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
        m.hasName("sendError") and
        ma.getNumArgument() = 2 and
        this.asExpr() = ma.getArgument(1)
        or
        m.hasName(["addAttribute", "addObject", "addFlashAttribute"]) and
        (
          m.getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.ui", "Model")
          or
          m.getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.ui", "ModelMap")
          or
          m.getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.web.servlet", "ModelAndView")
          or
          m.getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.web.servlet.mvc.support", "RedirectAttributes")
        )
      )
    )
  }
}

/** Treat common encoders/sanitizers as barriers when applied correctly. */
class XssSanitizer extends DataFlow::ExprNode {
  XssSanitizer() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      this.asExpr() = ma and
      (
        m.getDeclaringType().hasQualifiedName("org.owasp.encoder", "Encode") and
        m.getName().matches("for%")
        or
        m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "HtmlUtils") and
        m.hasName(["htmlEscape", "htmlEscapeDecimal", "htmlEscapeHex"])
        or
        m.getName() = "sanitize" and
        m.getDeclaringType().getQualifiedName().matches("%owasp%html%")
      )
    )
  }
}

class XssConfig extends TaintTracking::Configuration {
  XssConfig() { this = "JavaXssSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof XssSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof XssSanitizer
  }
}

from XssConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Response/view data depends on a $@.", source.getNode(), "user-controlled value"
