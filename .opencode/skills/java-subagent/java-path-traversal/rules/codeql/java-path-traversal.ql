/**
 * @name Java path traversal candidate paths
 * @description Finds flows from remote user input / Zip entry names / multipart
 *              filenames to file path construction and file I/O operations.
 * @kind path-problem
 * @problem.severity error
 * @id java/skill/path-traversal
 * @tags security external/cwe/cwe-22 external/cwe/cwe-23 external/cwe/cwe-36
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

/** Additional sources: Zip entry names and multipart original filenames. */
class PathTraversalExtraSource extends DataFlow::Node {
  PathTraversalExtraSource() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      this.asExpr() = ma and
      (
        m.hasName("getName") and
        (
          m.getDeclaringType().getASupertype*().hasQualifiedName("java.util.zip", "ZipEntry")
          or
          m.getDeclaringType().getASupertype*().hasQualifiedName("java.util.jar", "JarEntry")
          or
          m.getDeclaringType().getQualifiedName().matches("%ArchiveEntry%")
        )
        or
        m.hasName("getOriginalFilename") and
        m.getDeclaringType().getQualifiedName().matches("%MultipartFile%")
        or
        m.hasName("getSubmittedFileName") and
        (
          m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Part")
          or
          m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Part")
        )
      )
    )
  }
}

/** File path construction and I/O sinks. */
class PathTraversalSink extends DataFlow::ExprNode {
  PathTraversalSink() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      (
        (
          m.getDeclaringType().hasQualifiedName("java.io", "FileInputStream")
          or
          m.getDeclaringType().hasQualifiedName("java.io", "FileOutputStream")
          or
          m.getDeclaringType().hasQualifiedName("java.io", "FileReader")
          or
          m.getDeclaringType().hasQualifiedName("java.io", "FileWriter")
          or
          m.getDeclaringType().hasQualifiedName("java.io", "RandomAccessFile")
        ) and
        m.isConstructor() and
        this.asExpr() = ma.getArgument(0)
        or
        m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
        m.hasName([
            "readAllBytes", "readAllLines", "readString", "newInputStream", "newOutputStream",
            "write", "writeString", "delete", "deleteIfExists", "copy", "move", "createFile",
            "createDirectories", "newBufferedReader", "newBufferedWriter"
          ]) and
        this.asExpr() = ma.getArgument(0)
        or
        m.getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
        m.hasName(["resolve", "resolveSibling"]) and
        this.asExpr() = ma.getArgument(0)
        or
        m.getDeclaringType().hasQualifiedName("java.nio.file", "Paths") and
        m.hasName("get") and
        this.asExpr() = ma.getAnArgument()
      )
    )
    or
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.io", "File") and
      this.asExpr() = cie.getAnArgument()
    )
  }
}

class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() { this = "JavaPathTraversalSkillConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    or
    source instanceof PathTraversalExtraSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof PathTraversalSink
  }
}

from PathTraversalConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "File path operation depends on a $@.", source.getNode(), "user-controlled value"
