/**
 * @name Java JWT/JOSE misuse candidates
 * @description Finds alg=none, decode-without-verify, hardcoded HMAC secrets, and related JWT misuse.
 * @kind problem
 * @problem.severity error
 * @id java/skill/jwt-misuse
 * @tags security external/cwe/cwe-347 external/cwe/cwe-345 external/cwe/cwe-798
 */

import java

/** Auth0 JWT.decode - no signature verification. */
class Auth0Decode extends MethodAccess {
  Auth0Decode() {
    this.getMethod().hasQualifiedName("com.auth0.jwt", "JWT", "decode")
  }
}

/** Algorithm.none(). */
class AlgNone extends MethodAccess {
  AlgNone() {
    this.getMethod().getName() = "none" and
    this.getMethod().getDeclaringType().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm")
  }
}

/** HMAC256/384/512 with string literal secret. */
class HardcodedHmac extends MethodAccess {
  HardcodedHmac() {
    this.getMethod().getName().regexpMatch("HMAC(256|384|512)") and
    this.getMethod().getDeclaringType().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm") and
    this.getArgument(0) instanceof StringLiteral
  }
}

/** setSigningKey with string literal. */
class SetSigningKeyLiteral extends MethodAccess {
  SetSigningKeyLiteral() {
    this.getMethod().getName() = "setSigningKey" and
    (
      this.getArgument(0) instanceof StringLiteral
      or
      exists(MethodAccess ma |
        ma = this.getArgument(0).(MethodAccess) and
        ma.getMethod().hasName("getBytes") and
        ma.getQualifier() instanceof StringLiteral
      )
    )
  }
}

/** jjwt unsigned parse methods. */
class UnsignedJjwtParse extends MethodAccess {
  UnsignedJjwtParse() {
    this.getMethod().getName().regexpMatch("parseClaimsJwt|parseUnsecuredClaims")
  }
}

from Expr e, string msg
where
  (
    e instanceof Auth0Decode and msg = "JWT.decode does not verify signatures."
    or
    e instanceof AlgNone and msg = "Algorithm.none accepts unsigned JWTs."
    or
    e instanceof HardcodedHmac and msg = "Hardcoded HMAC secret for JWT."
    or
    e instanceof SetSigningKeyLiteral and msg = "setSigningKey with string literal secret."
    or
    e instanceof UnsignedJjwtParse and msg = "Unsigned JWT parse path (jjwt)."
  )
select e, msg
