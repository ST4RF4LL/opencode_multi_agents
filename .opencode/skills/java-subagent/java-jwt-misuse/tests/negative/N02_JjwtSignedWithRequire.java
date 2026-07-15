import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.security.PublicKey;
import java.util.Date;

public class N02_JjwtSignedWithRequire {
    private final PublicKey publicKey;
    private final String issuer;
    private final String audience;

    public N02_JjwtSignedWithRequire(PublicKey publicKey, String issuer, String audience) {
        this.publicKey = publicKey;
        this.issuer = issuer;
        this.audience = audience;
    }

    public Claims safe(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .requireIssuer(issuer)
                .requireAudience(audience)
                .build()
                .parseClaimsJws(token)
                .getBody();
        Date exp = claims.getExpiration();
        if (exp == null || exp.before(new Date())) {
            throw new IllegalArgumentException("expired");
        }
        return claims;
    }
}
