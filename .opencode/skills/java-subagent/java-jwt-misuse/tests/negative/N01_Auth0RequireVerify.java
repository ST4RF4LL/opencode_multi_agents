import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.security.interfaces.RSAPublicKey;

public class N01_Auth0RequireVerify {
    private final Algorithm algorithm;
    private final String issuer;
    private final String audience;

    public N01_Auth0RequireVerify(RSAPublicKey publicKey, String issuer, String audience) {
        this.algorithm = Algorithm.RSA256(publicKey, null);
        this.issuer = issuer;
        this.audience = audience;
    }

    public DecodedJWT safe(String token) {
        return JWT.require(algorithm)
                .withIssuer(issuer)
                .withAudience(audience)
                .build()
                .verify(token);
    }
}
