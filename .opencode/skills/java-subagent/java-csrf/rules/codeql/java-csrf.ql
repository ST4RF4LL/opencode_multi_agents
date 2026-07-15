/**
 * @name Java CSRF candidates
 * @description Finds Spring Security CSRF disable configuration and
 *              state-changing web handlers that rely on session/cookie auth patterns.
 * @kind problem
 * @problem.severity error
 * @id java/skill/csrf
 * @tags security external/cwe/cwe-352
 */

import java

/** Calls that disable Spring Security CSRF. */
class CsrfDisableCall extends MethodAccess {
  CsrfDisableCall() {
    this.getMethod().hasName("disable") and
    (
      this.getQualifier().getType().getName().matches("%Csrf%") or
      this.getQualifier().(MethodAccess).getMethod().hasName("csrf") or
      this.toString().matches("%csrf%disable%")
    )
  }
}

/** Spring MVC mapping annotations commonly used for mutations. */
class MutatingMappingAnnotation extends Annotation {
  MutatingMappingAnnotation() {
    this.getType().hasName("PostMapping") or
    this.getType().hasName("PutMapping") or
    this.getType().hasName("DeleteMapping") or
    this.getType().hasName("PatchMapping")
  }
}

/** GET mappings that look state-changing by name. */
class SuspiciousGetMapping extends Annotation {
  SuspiciousGetMapping() {
    this.getType().hasName("GetMapping") and
    exists(string v |
      v = this.getAValue().toString().toLowerCase() and
      (
        v.matches("%delete%") or
        v.matches("%remove%") or
        v.matches("%logout%") or
        v.matches("%transfer%") or
        v.matches("%update%")
      )
    )
  }
}

/** Methods that read session state (cookie-session signal). */
class SessionAccess extends MethodAccess {
  SessionAccess() {
    this.getMethod().hasName("getSession") or
    (
      this.getMethod().getDeclaringType().hasName("HttpSession") and
      (
        this.getMethod().hasName("getAttribute") or
        this.getMethod().hasName("setAttribute")
      )
    ) or
    this.getMethod().hasName("getContext") and
    this.getMethod().getDeclaringType().hasName("SecurityContextHolder")
  }
}

from CsrfDisableCall c
select c, "Spring Security CSRF appears disabled; verify cookie-auth state-changing endpoints."

// Companion queries (run as separate problems when integrated into a suite):
// 1) Methods annotated with MutatingMappingAnnotation that also call SessionAccess
// 2) Methods annotated with SuspiciousGetMapping that perform repository delete/save
