import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class N04_DecodeLoggingOnly {
    private static final Logger log = LoggerFactory.getLogger(N04_DecodeLoggingOnly.class);

    // Decode only for logging; auth uses separate verified path (documented non-trust use)
    public void logKidOnly(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            log.debug("jwt kid={}", jwt.getKeyId());
        } catch (Exception ignored) {
            log.debug("jwt parse skipped for logging");
        }
    }
}
