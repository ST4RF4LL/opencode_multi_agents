import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JwtService {
    private final SecretKey signingKey;

    public JwtService(SecretKey signingKey) {
        this.signingKey = signingKey;
    }

    public static JwtService fromEnv() {
        String secret = System.getenv("JWT_SIGNING_SECRET");
        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException("JWT_SIGNING_SECRET must be set (min 32 chars)");
        }
        SecretKey key = new SecretKeySpec(
            secret.getBytes(StandardCharsets.UTF_8),
            "HmacSHA256"
        );
        return new JwtService(key);
    }

    public String sign(String payload) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(signingKey);
        byte[] sig = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
    }
}
