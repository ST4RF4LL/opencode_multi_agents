// Pattern: JWT verified with HMAC but no exp/aud/iss claim validation
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

public class TokenParser {
    // FAKE test secret only — not for production use
    private static final SecretKey KEY =
            Keys.hmacShaKeyFor("TEST_ONLY_FAKE_SECRET_32B_MIN!!".getBytes(StandardCharsets.UTF_8));

    public Claims parse(String token) {
        // Verifies signature but does not require exp/aud/iss
        return Jwts.parserBuilder()
                .setSigningKey(KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
        // VULN: no requireExpiration / audience / issuer checks;
        // expired or wrong-audience tokens may still be accepted depending on library defaults
    }

    public boolean isAdmin(String token) {
        Claims claims = parse(token);
        // trusts claims without temporal/audience binding
        return "admin".equals(claims.get("role", String.class));
    }
}
