import io.shiftleft.semanticcpg.language._

val methods = cpg.method.l

methods.zipWithIndex.foreach { case (m, idx) =>

  val nodes = m.ast.l

  val nodeIds = nodes.map(_.id)

  println(s"EXPORT_METHOD_${idx}:${m.name}")

}