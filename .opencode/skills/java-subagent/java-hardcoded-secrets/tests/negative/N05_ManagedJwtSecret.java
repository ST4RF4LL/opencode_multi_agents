import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class N05_ManagedJwtSecret {
    private final SecretKey signingKey;

    public N05_ManagedJwtSecret(SecretKey signingKey) {
        this.signingKey = signingKey;
    }

    public static N05_ManagedJwtSecret fromEnv() {
        String secret = System.getenv("JWT_SIGNING_SECRET");
        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException("JWT_SIGNING_SECRET required");
        }
        return new N05_ManagedJwtSecret(
            new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256")
        );
    }

    public byte[] sign(String payload) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(signingKey);
        return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
    }
}
