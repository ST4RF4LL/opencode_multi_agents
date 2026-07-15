import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.security.PublicKey;

public class P05_AlgorithmConfusion {
    public DecodedJWT vulnerable(String token, PublicKey rsaPublicKey) {
        // VULN: RSA public key bytes used as HMAC secret (algorithm confusion)
        Algorithm algorithm = Algorithm.HMAC256(rsaPublicKey.getEncoded());
        return JWT.require(algorithm).build().verify(token);
    }
}
