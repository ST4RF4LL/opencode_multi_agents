/**
 * @name Java weak cryptography candidates
 * @description Finds use of weak algorithms, static IVs, insecure random, and weak password hashing.
 * @kind problem
 * @problem.severity error
 * @id java/skill/weak-cryptography
 * @tags security external/cwe/cwe-327 external/cwe/cwe-328 external/cwe/cwe-330
 */

import java

/** Cipher.getInstance with weak algorithm string. */
class WeakCipherCall extends MethodAccess {
  WeakCipherCall() {
    this.getMethod().hasQualifiedName("javax.crypto", "Cipher", "getInstance") and
    exists(CompileTimeConstantExpr c |
      c = this.getArgument(0) and
      (
        c.getStringValue().regexpMatch("(?i).*(DES|DESede|RC2|RC4|Blowfish).*")
        or
        c.getStringValue().regexpMatch("(?i)AES/ECB.*")
        or
        c.getStringValue() = "AES"
        or
        c.getStringValue().regexpMatch("(?i)RSA(/ECB/PKCS1Padding)?")
      )
    )
  }
}

/** MessageDigest with MD5 or SHA-1. */
class WeakDigestCall extends MethodAccess {
  WeakDigestCall() {
    this.getMethod().hasQualifiedName("java.security", "MessageDigest", "getInstance") and
    exists(CompileTimeConstantExpr c |
      c = this.getArgument(0) and
      c.getStringValue().regexpMatch("(?i)MD5|SHA-?1")
    )
  }
}

/** java.util.Random construction. */
class InsecureRandom extends ClassInstanceExpr {
  InsecureRandom() {
    this.getConstructedType().hasQualifiedName("java.util", "Random")
  }
}

/** SecretKeySpec with string literal key material. */
class HardcodedKeySpec extends ClassInstanceExpr {
  HardcodedKeySpec() {
    this.getConstructedType().hasQualifiedName("javax.crypto.spec", "SecretKeySpec") and
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

from Expr e, string msg
where
  (
    e instanceof WeakCipherCall and msg = "Weak or risky Cipher algorithm/mode."
    or
    e instanceof WeakDigestCall and msg = "Weak MessageDigest algorithm (MD5/SHA-1)."
    or
    e instanceof InsecureRandom and msg = "java.util.Random may be used for security-sensitive values."
    or
    e instanceof HardcodedKeySpec and msg = "Hardcoded key material in SecretKeySpec."
  )
select e, msg
