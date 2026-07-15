import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class P03_SecretKeySpecJwt {
    public byte[] vulnerable(String payload) throws Exception {
        String secret = "jwt-secret-CHANGE_ME_NOT_REAL";
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
    }
}
