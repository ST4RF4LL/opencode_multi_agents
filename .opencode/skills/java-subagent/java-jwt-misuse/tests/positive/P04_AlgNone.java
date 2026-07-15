import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class P04_AlgNone {
    public DecodedJWT vulnerable(String token) {
        return JWT.require(Algorithm.none()).build().verify(token);
    }
}
