// Expand callers from binding/persistence methods to build call chains (L1/L2 assist).

  val methods = cpg.method.fullName(sinkMethod).l
  methods.foreach { m =>
    println(s"sink_method=${m.fullName}")
    m.caller.foreach { c =>
      println(s"  caller=${c.fullName}\tfile=${c.filename}\tline=${c.lineNumber.getOrElse(-1)}")
      c.caller.take(20).foreach { cc =>
        println(s"    caller2=${cc.fullName}\tfile=${cc.filename}")
      }
    }
  }

  val controllers = cpg.method
    .where(_.annotation.name("RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping"))
    .l

  controllers.foreach { m =>
    val hasBody = m.parameter.annotation.name("RequestBody|ModelAttribute").nonEmpty
    if (hasBody) {
      println(
        s"controller_binding\tmethod=${m.fullName}\t" +
        s"file=${m.filename}\tline=${m.lineNumber.getOrElse(-1)}\t" +
        s"params=${m.parameter.map(p => s"${p.name}:${p.typeFullName}").mkString(",")}"
      )
    }
  }
}
