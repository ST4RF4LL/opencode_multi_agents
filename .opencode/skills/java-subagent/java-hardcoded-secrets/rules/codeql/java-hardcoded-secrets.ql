/**
 * @name Java hardcoded secrets candidates
 * @description Finds hardcoded passwords, API keys, SecretKeySpec literals, and AWS static credentials.
 * @kind problem
 * @problem.severity error
 * @id java/skill/hardcoded-secrets
 * @tags security external/cwe/cwe-798 external/cwe/cwe-259 external/cwe/cwe-321
 */

import java

/** SecretKeySpec constructed from string literal getBytes or string. */
class HardcodedSecretKeySpec extends ClassInstanceExpr {
  HardcodedSecretKeySpec() {
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

/** DriverManager.getConnection with password string literal. */
class HardcodedJdbcPassword extends MethodAccess {
  HardcodedJdbcPassword() {
    this.getMethod().hasQualifiedName("java.sql", "DriverManager", "getConnection") and
    this.getNumArgument() >= 3 and
    this.getArgument(2) instanceof StringLiteral
  }
}

/** AWS BasicAWSCredentials with string literals. */
class HardcodedAwsBasicCredentials extends ClassInstanceExpr {
  HardcodedAwsBasicCredentials() {
    (
      this.getConstructedType().hasQualifiedName("com.amazonaws.auth", "BasicAWSCredentials")
      or
      this.getConstructedType()
          .hasQualifiedName("software.amazon.awssdk.auth.credentials", "AwsBasicCredentials")
    ) and
    this.getArgument(0) instanceof StringLiteral and
    this.getArgument(1) instanceof StringLiteral
  }
}

/** Field or variable named like a secret assigned a string literal. */
class HardcodedNamedSecret extends AssignExpr {
  HardcodedNamedSecret() {
    this.getSource() instanceof StringLiteral and
    exists(string n |
      n = this.getDest().(VarAccess).getVariable().getName() and
      n.regexpMatch("(?i).*(password|passwd|secret|apiKey|api_key|token|accessKey|clientSecret|privateKey).*")
    )
  }
}

/** AKIA-shaped string literal. */
class AkiaLiteral extends StringLiteral {
  AkiaLiteral() { this.getValue().regexpMatch("AKIA[0-9A-Z]{16}") }
}

from Expr e, string msg
where
  (
    e instanceof HardcodedSecretKeySpec and
    msg = "Hardcoded key material in SecretKeySpec."
    or
    e instanceof HardcodedJdbcPassword and
    msg = "Hardcoded JDBC password argument."
    or
    e instanceof HardcodedAwsBasicCredentials and
    msg = "Hardcoded AWS static credentials."
    or
    e instanceof HardcodedNamedSecret and
    msg = "Secret-named variable assigned string literal."
    or
    e instanceof AkiaLiteral and
    msg = "AWS access key id pattern in string literal."
  )
select e, msg
