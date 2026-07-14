import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class N02_BcryptPassword {
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public String safe(String password) {
        return encoder.encode(password);
    }
}
