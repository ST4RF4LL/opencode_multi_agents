import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class P02_HardcodedHmacSecret {
    // FAKE secret for test fixture only
    private static final String SECRET = "secret";

    public DecodedJWT vulnerable(String token) {
        return JWT.require(Algorithm.HMAC256(SECRET)).build().verify(token);
    }
}
