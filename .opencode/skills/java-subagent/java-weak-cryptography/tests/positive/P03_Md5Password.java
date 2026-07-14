import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class P03_Md5Password {
    public String vulnerable(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] dig = md.digest(password.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : dig) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
