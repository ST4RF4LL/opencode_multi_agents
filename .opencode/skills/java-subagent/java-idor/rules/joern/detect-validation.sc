// L3 assist: find nearby ownership/tenant/authz patterns around IDOR sinks.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)

  val sinks = cpg.call.methodFullName(
    ".*JpaRepository\\.findById.*|" +
    ".*CrudRepository\\.findById.*|" +
    ".*Repository\\.findById.*|" +
    ".*JpaRepository\\.deleteById.*|" +
    ".*CrudRepository\\.deleteById.*|" +
    ".*JpaRepository\\.save.*|" +
    ".*EntityManager\\.find.*|" +
    ".*EntityManager\\.remove.*|" +
    ".*Mapper\\.selectByPrimaryKey.*|" +
    ".*Mapper\\.deleteByPrimaryKey.*"
  ).l

  sinks.foreach { s =>
    val m = s.method
    val hasSecurityContext = m.code.contains("SecurityContextHolder") ||
      m.code.contains("getAuthentication") ||
      m.code.contains("getPrincipal") ||
      m.call.name("getName|getPrincipal|getAuthentication").nonEmpty
    val hasOwnerCompare = m.call.name("equals|equalsIgnoreCase").nonEmpty &&
      (m.code.contains("userId") || m.code.contains("ownerId") || m.code.contains("getUser") ||
        m.code.contains("getOwner") || m.code.contains("createdBy"))
    val hasTenant = m.code.contains("tenantId") || m.code.contains("getTenant") ||
      m.code.contains("TenantContext")
    val hasPreAuthorize = m.annotation.name("PreAuthorize|PostAuthorize|Secured|RolesAllowed").nonEmpty ||
      m.code.contains("PreAuthorize") || m.code.contains("PostAuthorize")
    val hasFindByIdAndUser = m.code.contains("findByIdAndUser") ||
      m.code.contains("findByIdAndOwner") || m.code.contains("AndUserId") ||
      m.code.contains("AndTenantId")
    val hasAuthOnly = m.code.contains("isAuthenticated") ||
      m.annotation.name("Authenticated").nonEmpty

    println(
      s"control_context\tfile=${s.file.name.headOption.getOrElse("?")}\t" +
      s"line=${s.lineNumber.getOrElse(-1)}\t" +
      s"method=${m.fullName}\t" +
      s"has_security_context=$hasSecurityContext\t" +
      s"has_owner_compare=$hasOwnerCompare\t" +
      s"has_tenant_ref=$hasTenant\t" +
      s"has_pre_post_authorize=$hasPreAuthorize\t" +
      s"has_find_by_id_and_user=$hasFindByIdAndUser\t" +
      s"has_auth_only_hint=$hasAuthOnly\t" +
      s"sink=${s.methodFullName}"
    )
  }
}
