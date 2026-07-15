/**
 * @name Java XXE candidate paths
 * @description Finds flows from remote user input to XML parse/unmarshal APIs.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/xxe
 * @tags security external/cwe/cwe-611 external/cwe/cwe-827 external/cwe/cwe-776
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** XML parse / unmarshal sinks commonly abused for XXE. */
class XmlParseSink extends DataFlow::ExprNode {
  XmlParseSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      this.asExpr() = ma.getAnArgument() and
      (
        (
          m.hasName("parse") and
          (
            m.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.parsers", "DocumentBuilder")
            or
            m.getDeclaringType().getASupertype*().hasQualifiedName("jakarta.xml.parsers", "DocumentBuilder")
            or
            m.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.parsers", "SAXParser")
            or
            m.getDeclaringType().getASupertype*().hasQualifiedName("jakarta.xml.parsers", "SAXParser")
            or
            m.getDeclaringType().getASupertype*().hasQualifiedName("org.xml.sax", "XMLReader")
          )
        )
        or
        (
          (m.hasName("createXMLStreamReader") or m.hasName("createXMLEventReader")) and
          (
            m.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.stream", "XMLInputFactory")
            or
            m.getDeclaringType().getASupertype*().hasQualifiedName("jakarta.xml.stream", "XMLInputFactory")
          )
        )
        or
        (
          m.hasName("unmarshal") and
          (
            m.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.bind", "Unmarshaller")
            or
            m.getDeclaringType().getASupertype*().hasQualifiedName("jakarta.xml.bind", "Unmarshaller")
            or
            m.getDeclaringType().getQualifiedName().matches("%Unmarshaller%")
          )
        )
        or
        (
          (m.hasName("newTransformer") or m.hasName("newTemplates") or m.hasName("transform")) and
          (
            m.getDeclaringType().getQualifiedName().matches("%TransformerFactory%")
            or
            m.getDeclaringType().getQualifiedName().matches("%Transformer")
          )
        )
        or
        (
          m.hasName("read") and
          m.getDeclaringType().getQualifiedName().matches("%SAXReader%")
        )
        or
        (
          m.hasName("build") and
          m.getDeclaringType().getQualifiedName().matches("%SAXBuilder%")
        )
        or
        (
          m.hasName("parseText") and
          m.getDeclaringType().getQualifiedName().matches("%DocumentHelper%")
        )
      )
    )
  }
}

class XxeConfig extends TaintTracking::Configuration {
  XxeConfig() { this = "JavaXxeSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof XmlParseSink
  }
}

from XxeConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "XML parse/unmarshal depends on a $@. Verify secure parser features on the same factory.",
  source.getNode(), "user-controlled value"
