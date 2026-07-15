/**
 * @name Java unsafe deserialization candidate paths
 * @description Finds flows from remote user input to deserialization APIs.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/unsafe-deserialization
 * @tags security external/cwe/cwe-502
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** Deserialization-related sinks. */
class UnsafeDeserializationSink extends DataFlow::ExprNode {
  UnsafeDeserializationSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      (
        // Argument is the untrusted data
        (
          this.asExpr() = ma.getAnArgument() and
          (
            m.hasName(["parse", "parseObject", "parseArray"]) and
            (
              m.getDeclaringType().getQualifiedName().matches("%fastjson%JSON%")
              or
              m.getDeclaringType().hasQualifiedName("com.alibaba.fastjson", "JSONObject")
              or
              m.getDeclaringType().hasQualifiedName("com.alibaba.fastjson2", "JSON")
            )
            or
            m.hasName("readValue") and
            m.getDeclaringType().getASupertype*().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper")
            or
            m.hasName(["load", "loadAll", "loadAs"]) and
            m.getDeclaringType().hasQualifiedName("org.yaml.snakeyaml", "Yaml")
            or
            m.hasName(["fromXML", "unmarshal"]) and
            m.getDeclaringType().getQualifiedName().matches("%xstream%XStream%")
            or
            m.hasName(["readObject", "readClassAndObject"]) and
            (
              m.getDeclaringType().getQualifiedName().matches("%kryo%Kryo%")
              or
              m.getDeclaringType().getQualifiedName().matches("%hessian%")
            )
            or
            m.hasName("deserialize") and
            (
              m.getDeclaringType().hasQualifiedName("org.springframework.util", "SerializationUtils")
              or
              m.getDeclaringType().getQualifiedName().matches("%RedisSerializer%")
              or
              m.getDeclaringType().getQualifiedName().matches("%JdkSerializationRedisSerializer%")
            )
          )
        )
        or
        // Receiver stream constructed from untrusted data (track constructor arg separately via taint)
        (
          m.hasName(["readObject", "readUnshared"]) and
          m.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
          this.asExpr() = ma.getQualifier()
        )
        or
        (
          m.hasName("readObject") and
          m.getDeclaringType().hasQualifiedName("java.beans", "XMLDecoder") and
          this.asExpr() = ma.getQualifier()
        )
      )
    )
    or
    // ObjectInputStream constructor argument
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.io", "ObjectInputStream") and
      this.asExpr() = cie.getAnArgument()
    )
    or
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.beans", "XMLDecoder") and
      this.asExpr() = cie.getAnArgument()
    )
  }
}

class UnsafeDeserializationConfig extends TaintTracking::Configuration {
  UnsafeDeserializationConfig() { this = "JavaUnsafeDeserializationSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof UnsafeDeserializationSink
  }
}

from UnsafeDeserializationConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Deserialization depends on a $@.", source.getNode(), "user-controlled value"
