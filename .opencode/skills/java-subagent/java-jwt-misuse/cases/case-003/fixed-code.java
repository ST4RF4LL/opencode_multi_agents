import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.security.PublicKey;
import java.util.Date;

public class TokenParser {
    private final PublicKey publicKey;
    private final String expectedIssuer;
    private final String expectedAudience;

    public TokenParser(PublicKey publicKey, String expectedIssuer, String expectedAudience) {
        this.publicKey = publicKey;
        this.expectedIssuer = expectedIssuer;
        this.expectedAudience = expectedAudience;
    }

    public Claims parse(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .requireIssuer(expectedIssuer)
                .requireAudience(expectedAudience)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Date exp = claims.getExpiration();
        if (exp == null || exp.before(new Date())) {
            throw new IllegalArgumentException("token expired or missing exp");
        }
        return claims;
    }

    public boolean isAdmin(String token) {
        Claims claims = parse(token);
        return "admin".equals(claims.get("role", String.class));
    }
}
