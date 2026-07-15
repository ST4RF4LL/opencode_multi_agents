import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

public class P01_DecodeWithoutVerify {
    public String vulnerable(String token) {
        DecodedJWT jwt = JWT.decode(token);
        return jwt.getSubject();
    }
}
