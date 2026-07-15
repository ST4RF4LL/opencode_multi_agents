// L2: source-to-sink dataflow for unsafe file upload candidates.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sourceCalls = cpg.call.methodFullName(
  ".*MultipartFile\\.getOriginalFilename.*|" +
  ".*MultipartFile\\.getContentType.*|" +
  ".*MultipartFile\\.getBytes.*|" +
  ".*MultipartFile\\.getInputStream.*|" +
  ".*Part\\.getSubmittedFileName.*|" +
  ".*Part\\.getContentType.*|" +
  ".*Part\\.getInputStream.*|" +
  ".*FileItem\\.getName.*|" +
  ".*FileItem\\.getContentType.*|" +
  ".*FileItem\\.getInputStream.*|" +
  ".*FileItem\\.get.*"
).argument

val annotatedSources = cpg.parameter
  .where(_.annotation.name("RequestPart|RequestParam|RequestBody"))

val sinks = cpg.call.methodFullName(
  ".*MultipartFile\\.transferTo.*|" +
  ".*Part\\.write.*|" +
  ".*FileItem\\.write.*|" +
  ".*Files\\.copy.*|" +
  ".*Files\\.write.*|" +
  ".*Files\\.newOutputStream.*|" +
  ".*FileOutputStream\\.<init>.*|" +
  ".*java\\.io\\.File\\.<init>.*|" +
  ".*Path\\.resolve.*"
).argument

val flowsFromCalls = sinks.reachableByFlows(sourceCalls).l
val flowsFromParams = sinks.reachableByFlows(annotatedSources).l
val flows = flowsFromCalls ++ flowsFromParams

flows.zipWithIndex.foreach { case (flow, idx) =>
  println(s"dataflow_id=UPLOAD-FLOW-$idx")
  flow.elements.foreach { e =>
    println(
      s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
      s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
    )
  }
}

println(s"total_flows=${flows.size}")
