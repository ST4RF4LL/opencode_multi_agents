/**
 * @name Java SSRF candidate paths
 * @description Finds flows from remote user input to server-side HTTP/URL open APIs.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/ssrf
 * @tags security external/cwe/cwe-918
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** Common server-side request sinks for SSRF analysis. */
class SsrfSink extends DataFlow::ExprNode {
  SsrfSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      (
        (
          m.hasName("openConnection") or
          m.hasName("openStream") or
          m.hasName("getContent")
        ) and
        m.getDeclaringType().hasQualifiedName("java.net", "URL") and
        this.asExpr() = ma.getQualifier()
        or
        (
          m.hasName("exchange") or
          m.hasName("getForObject") or
          m.hasName("getForEntity") or
          m.hasName("postForObject") or
          m.hasName("postForEntity") or
          m.hasName("execute")
        ) and
        m.getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.web.client", "RestTemplate") and
        this.asExpr() = ma.getArgument(0)
        or
        m.hasName("url") and
        m.getDeclaringType().getQualifiedName().matches("%Request$Builder%") and
        this.asExpr() = ma.getArgument(0)
        or
        m.hasName("uri") and
        (
          m.getDeclaringType().getQualifiedName().matches("%WebClient%") or
          m.getDeclaringType().getQualifiedName().matches("%HttpRequest$Builder%")
        ) and
        this.asExpr() = ma.getArgument(0)
        or
        m.hasName("execute") and
        m.getDeclaringType().getQualifiedName().matches("%HttpClient%") and
        this.asExpr() = ma.getArgument(0)
      )
    )
    or
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.net", "URL") and
      this.asExpr() = cie.getArgument(0)
    )
    or
    exists(ClassInstanceExpr cie |
      (
        cie.getConstructedType().getName() = "HttpGet" or
        cie.getConstructedType().getName() = "HttpPost"
      ) and
      this.asExpr() = cie.getArgument(0)
    )
  }
}

class SsrfConfig extends TaintTracking::Configuration {
  SsrfConfig() { this = "JavaSsrfSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SsrfSink
  }
}

from SsrfConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Server-side request depends on a $@.", source.getNode(), "user-controlled value"
