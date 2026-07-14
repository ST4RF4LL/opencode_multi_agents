import java.security.SecureRandom;
import java.util.Base64;

public class N03_SecureRandomToken {
    private final SecureRandom random = new SecureRandom();

    public String safeSessionToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
