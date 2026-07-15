import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

public class P03_NoExpAudCheck {
    // FAKE test-only key material
    private final SecretKey key =
            Keys.hmacShaKeyFor("TEST_ONLY_FAKE_SECRET_32B_MIN!!".getBytes(StandardCharsets.UTF_8));

    public Claims vulnerable(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
