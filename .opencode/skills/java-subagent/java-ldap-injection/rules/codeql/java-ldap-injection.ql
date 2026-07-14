/**
 * @name Java LDAP injection candidate paths
 * @description Finds flows from remote user input to LDAP search filter or DN APIs.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/ldap-injection
 * @tags security external/cwe/cwe-090
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** LDAP-related sinks commonly abused for injection. */
class LdapSink extends DataFlow::ExprNode {
  LdapSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      (
        // DirContext.search — filter or base name arguments
        m.getDeclaringType().getASupertype*().hasQualifiedName("javax.naming.directory", "DirContext") and
        m.hasName("search") and
        (this.asExpr() = ma.getArgument(0) or this.asExpr() = ma.getArgument(1))
        or
        m.getDeclaringType().getASupertype*().hasQualifiedName("jakarta.naming.directory", "DirContext") and
        m.hasName("search") and
        (this.asExpr() = ma.getArgument(0) or this.asExpr() = ma.getArgument(1))
        or
        // Context.lookup / bind with DN
        m.getDeclaringType().getASupertype*().hasQualifiedName("javax.naming", "Context") and
        m.hasName(["lookup", "bind", "rebind"]) and
        this.asExpr() = ma.getArgument(0)
        or
        // Spring LdapTemplate
        m.getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.ldap.core", "LdapTemplate") and
        m.hasName(["search", "searchForObject", "authenticate", "lookup", "find", "findOne"]) and
        (this.asExpr() = ma.getArgument(0) or this.asExpr() = ma.getArgument(1))
        or
        // HardcodedFilter constructor
        m.getDeclaringType().hasQualifiedName("org.springframework.ldap.filter", "HardcodedFilter") and
        m.isConstructor() and
        this.asExpr() = ma.getArgument(0)
      )
    )
  }
}

class LdapInjectionConfig extends TaintTracking::Configuration {
  LdapInjectionConfig() { this = "JavaLdapInjectionSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof LdapSink
  }
}

from LdapInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "LDAP operation depends on a $@.", source.getNode(), "user-controlled value"
