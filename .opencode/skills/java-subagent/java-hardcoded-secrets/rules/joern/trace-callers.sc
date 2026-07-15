// Expand callers from secret-binding sink methods to build call chains.
@main def exec(cpgFile: String, sinkMethod: String = ".*SecretKeySpec\\.<init>.*") = {
  importCpg(cpgFile)

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

  val related = cpg.call.methodFullName(
    ".*SecretKeySpec.*|.*DriverManager\\.getConnection.*|" +
    ".*BasicAWSCredentials.*|.*AwsBasicCredentials.*|" +
    ".*hmacShaKeyFor.*|.*setPassword.*"
  ).method.l.distinct

  related.foreach { m =>
    println(s"secret_user_method=${m.fullName}\tfile=${m.filename}")
  }
}
