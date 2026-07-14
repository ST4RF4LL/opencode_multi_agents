import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Non-security checksum / cache key only. */
public class N04_Sha256Checksum {
    public String cacheKey(String content) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] dig = md.digest(content.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : dig) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
