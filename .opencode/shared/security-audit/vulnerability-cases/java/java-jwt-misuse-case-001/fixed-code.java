import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.security.interfaces.RSAPublicKey;

public class AuthFilter extends OncePerRequestFilter {
    private final JWTVerifier verifier;

    public AuthFilter(RSAPublicKey publicKey, String issuer, String audience) {
        Algorithm algorithm = Algorithm.RSA256(publicKey, null);
        this.verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .withAudience(audience)
                .build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws java.io.IOException, jakarta.servlet.ServletException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        try {
            DecodedJWT jwt = verifier.verify(header.substring(7));
            request.setAttribute("userId", jwt.getSubject());
            request.setAttribute("role", jwt.getClaim("role").asString());
            chain.doFilter(request, response);
        } catch (Exception ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
