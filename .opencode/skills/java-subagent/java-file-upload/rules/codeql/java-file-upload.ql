/**
 * @name Java unsafe file upload candidate paths
 * @description Finds flows from multipart/upload inputs (filename, content type,
 *              file body) to file storage operations without assuming exploit payloads.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/file-upload
 * @tags security external/cwe/cwe-434
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** Multipart filename, content type, and body sources. */
class FileUploadExtraSource extends DataFlow::Node {
  FileUploadExtraSource() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      this.asExpr() = ma and
      (
        m.hasName("getOriginalFilename") and
        m.getDeclaringType().getQualifiedName().matches("%MultipartFile%")
        or
        m.hasName("getSubmittedFileName") and
        (
          m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Part")
          or
          m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Part")
        )
        or
        m.hasName("getName") and
        m.getDeclaringType().getQualifiedName().matches("%FileItem%")
        or
        m.hasName("getContentType") and
        (
          m.getDeclaringType().getQualifiedName().matches("%MultipartFile%")
          or
          m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Part")
          or
          m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Part")
          or
          m.getDeclaringType().getQualifiedName().matches("%FileItem%")
        )
        or
        m.hasName(["getBytes", "getInputStream", "get"]) and
        (
          m.getDeclaringType().getQualifiedName().matches("%MultipartFile%")
          or
          m.getDeclaringType().getQualifiedName().matches("%FileItem%")
          or
          m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Part")
          or
          m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Part")
        )
      )
    )
  }
}

/** Upload storage and path construction sinks. */
class FileUploadSink extends DataFlow::ExprNode {
  FileUploadSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      (
        m.hasName("transferTo") and
        m.getDeclaringType().getQualifiedName().matches("%MultipartFile%") and
        this.asExpr() = ma.getArgument(0)
        or
        m.hasName("write") and
        (
          m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Part")
          or
          m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Part")
          or
          m.getDeclaringType().getQualifiedName().matches("%FileItem%")
        ) and
        this.asExpr() = ma.getArgument(0)
        or
        m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
        m.hasName(["copy", "write", "writeString", "newOutputStream"]) and
        this.asExpr() = ma.getAnArgument()
        or
        m.getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
        m.hasName("resolve") and
        this.asExpr() = ma.getArgument(0)
      )
    )
    or
    exists(ClassInstanceExpr cie |
      (
        cie.getConstructedType().hasQualifiedName("java.io", "FileOutputStream")
        or
        cie.getConstructedType().hasQualifiedName("java.io", "File")
      ) and
      this.asExpr() = cie.getAnArgument()
    )
  }
}

class FileUploadConfig extends TaintTracking::Configuration {
  FileUploadConfig() { this = "JavaFileUploadSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    or
    source instanceof FileUploadExtraSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileUploadSink
  }
}

from FileUploadConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "File upload storage depends on a $@.", source.getNode(), "user-controlled upload value"
