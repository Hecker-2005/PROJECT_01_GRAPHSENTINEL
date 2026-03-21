// extract_functions.sc

import io.shiftleft.semanticcpg.language._

val methods = cpg.method.l

println(s"Total methods: ${methods.size}")

methods.zipWithIndex.foreach { case (m, idx) =>

  val nodes = m.ast.l

  println(s"METHOD_${idx}:${m.name}")

}