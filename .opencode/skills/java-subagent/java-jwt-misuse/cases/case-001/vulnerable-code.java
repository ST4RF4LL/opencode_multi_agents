// Pattern: parse/decode JWT without signature verification
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

public class AuthFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws java.io.IOException, jakarta.servlet.ServletException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            // VULN: decode only — no cryptographic verify
            DecodedJWT jwt = JWT.decode(token);
            request.setAttribute("userId", jwt.getSubject());
            request.setAttribute("role", jwt.getClaim("role").asString());
        }
        chain.doFilter(request, response);
    }
}
