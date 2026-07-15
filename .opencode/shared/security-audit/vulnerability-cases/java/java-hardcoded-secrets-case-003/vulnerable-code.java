// Pattern: SecretKeySpec hardcoded for JWT/AES HMAC signing
// Secret string is obviously fake sample material only.
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JwtService {
    private static final String SECRET = "jwt-secret-CHANGE_ME_NOT_REAL";

    public String sign(String payload) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec key = new SecretKeySpec(
            SECRET.getBytes(StandardCharsets.UTF_8),
            "HmacSHA256"
        );
        mac.init(key);
        byte[] sig = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
    }
}
