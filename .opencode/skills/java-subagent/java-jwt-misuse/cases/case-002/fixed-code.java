import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class JwtService {
    private final JWTVerifier verifier;
    private final Algorithm signAlgorithm;

    public JwtService(RSAPublicKey publicKey, RSAPrivateKey privateKey,
                      String issuer, String audience) {
        this.signAlgorithm = Algorithm.RSA256(publicKey, privateKey);
        this.verifier = JWT.require(Algorithm.RSA256(publicKey, null))
                .withIssuer(issuer)
                .withAudience(audience)
                .build();
    }

    public DecodedJWT verify(String token) {
        return verifier.verify(token);
    }

    public String issue(String subject) {
        return JWT.create()
                .withSubject(subject)
                .withIssuer("https://issuer.example.invalid")
                .withAudience("api")
                .sign(signAlgorithm);
    }
}
