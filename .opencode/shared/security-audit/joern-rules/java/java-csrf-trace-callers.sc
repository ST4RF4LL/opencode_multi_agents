// Expand callers from state-write methods to web entry handlers (L1/L2 assist).

  val methods = cpg.method.fullName(sinkMethod).l
  methods.foreach { m =>
    println(s"sink_method=${m.fullName}")
    m.caller.foreach { c =>
      val annos = c.annotation.name.l.mkString(",")
      println(
        s"  caller=${c.fullName}\tfile=${c.filename}\t" +
        s"line=${c.lineNumber.getOrElse(-1)}\tannotations=$annos"
      )
      c.caller.take(20).foreach { cc =>
        val a2 = cc.annotation.name.l.mkString(",")
        println(s"    caller2=${cc.fullName}\tfile=${cc.filename}\tannotations=$a2")
      }
    }
  }
}
