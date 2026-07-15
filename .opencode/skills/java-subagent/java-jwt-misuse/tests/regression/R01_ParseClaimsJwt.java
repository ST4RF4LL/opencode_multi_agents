import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class R01_ParseClaimsJwt {
    // Regression: unsigned jjwt path must remain a candidate
    public Claims vulnerable(String token) {
        return Jwts.parser().parseClaimsJwt(token).getBody();
    }
}
