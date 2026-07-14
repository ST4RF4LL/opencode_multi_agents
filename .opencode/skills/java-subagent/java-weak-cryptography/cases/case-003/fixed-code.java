import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordUtil {
    private static final PasswordEncoder ENCODER = new BCryptPasswordEncoder();

    public static String hash(String password) {
        return ENCODER.encode(password);
    }

    public static boolean matches(String raw, String encoded) {
        return ENCODER.matches(raw, encoded);
    }
}
