// L2: source-to-sink dataflow for unsafe deserialization candidates.

// Adapted for OpenCode Joern MCP: CPG is pre-loaded via `joern cpg.bin --script`.
// Original entry: @main def exec(cpgFile: String)
// Do not call importCpg; use the ambient `cpg` symbol.

val sourceCalls = cpg.call.methodFullName(
  ".*HttpServletRequest\\.getParameter.*|" +
  ".*HttpServletRequest\\.getHeader.*|" +
  ".*HttpServletRequest\\.getInputStream.*|" +
  ".*Cookie\\.getValue.*|" +
  ".*MultipartFile\\.getBytes.*|" +
  ".*Base64\\.Decoder\\.decode.*|" +
  ".*Base64\\.getDecoder\\.decode.*|" +
  ".*Message\\.getBody.*|" +
  ".*Message\\.getPayload.*|" +
  ".*ConsumerRecord\\.value.*|" +
  ".*Jedis\\.get.*|" +
  ".*IOUtils\\.toByteArray.*|" +
  ".*StreamUtils\\.copyToByteArray.*"
).argument

val annotatedSources = cpg.parameter
  .where(_.annotation.name("RequestParam|PathVariable|RequestHeader|RequestBody|CookieValue"))

val sinks = cpg.call.methodFullName(
  ".*ObjectInputStream\\.readObject.*|" +
  ".*ObjectInputStream\\.readUnshared.*|" +
  ".*XMLDecoder\\.readObject.*|" +
  ".*com\\.alibaba\\.fastjson\\.JSON\\.parse.*|" +
  ".*com\\.alibaba\\.fastjson\\.JSON\\.parseObject.*|" +
  ".*com\\.alibaba\\.fastjson2\\.JSON\\.parse.*|" +
  ".*com\\.alibaba\\.fastjson2\\.JSON\\.parseObject.*|" +
  ".*ObjectMapper\\.readValue.*|" +
  ".*org\\.yaml\\.snakeyaml\\.Yaml\\.load.*|" +
  ".*XStream\\.fromXML.*|" +
  ".*Hessian2Input\\.readObject.*|" +
  ".*HessianInput\\.readObject.*|" +
  ".*Kryo\\.readObject.*|" +
  ".*Kryo\\.readClassAndObject.*|" +
  ".*JdkSerializationRedisSerializer\\.deserialize.*|" +
  ".*SerializationUtils\\.deserialize.*"
)

// Argument-sensitive sinks (parse/load/fromXML/deserialize)
val argSinks = sinks
  .methodFullName(
    ".*JSON\\.parse.*|" +
    ".*JSON\\.parseObject.*|" +
    ".*ObjectMapper\\.readValue.*|" +
    ".*Yaml\\.load.*|" +
    ".*XStream\\.fromXML.*|" +
    ".*Kryo\\.readObject.*|" +
    ".*Kryo\\.readClassAndObject.*|" +
    ".*deserialize.*"
  )
  .argument(1)

// Receiver-sensitive sinks (readObject on stream)
val recvSinks = sinks
  .methodFullName(
    ".*ObjectInputStream\\.readObject.*|" +
    ".*ObjectInputStream\\.readUnshared.*|" +
    ".*XMLDecoder\\.readObject.*|" +
    ".*Hessian2Input\\.readObject.*|" +
    ".*HessianInput\\.readObject.*"
  )
  .argument(0)

val sinkNodes = argSinks ++ recvSinks
val flowsFromCalls = sinkNodes.reachableByFlows(sourceCalls).l
val flowsFromParams = sinkNodes.reachableByFlows(annotatedSources).l
val flows = flowsFromCalls ++ flowsFromParams

flows.zipWithIndex.foreach { case (flow, idx) =>
  println(s"dataflow_id=DESER-FLOW-$idx")
  flow.elements.foreach { e =>
    println(
      s"  step\tfile=${e.file.name.headOption.getOrElse("?")}\t" +
      s"line=${e.lineNumber.getOrElse(-1)}\tcode=${e.code}"
    )
  }
}

println(s"total_flows=${flows.size}")
