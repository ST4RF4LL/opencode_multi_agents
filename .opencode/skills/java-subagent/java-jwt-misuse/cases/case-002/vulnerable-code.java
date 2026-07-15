// Pattern: hardcoded weak HMAC secret for JWT
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class JwtService {
    // VULN: trivial hardcoded secret (FAKE — test only)
    private static final String SECRET = "secret";

    public DecodedJWT verify(String token) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET);
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(token);
    }

    public String issue(String subject) {
        return JWT.create()
                .withSubject(subject)
                .sign(Algorithm.HMAC256(SECRET));
    }
}
