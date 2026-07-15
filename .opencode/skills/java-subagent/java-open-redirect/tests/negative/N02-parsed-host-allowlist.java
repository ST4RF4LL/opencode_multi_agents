import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Set;

public class N02_parsed_host_allowlist {
    private static final Set<String> ALLOWED_HOSTS = Set.of("app.example.com");

    public void safe(HttpServletResponse response, String next) throws IOException {
        URI uri = URI.create(next);
        if (!"https".equalsIgnoreCase(uri.getScheme())
            || uri.getHost() == null
            || !ALLOWED_HOSTS.contains(uri.getHost().toLowerCase())) {
            throw new IllegalArgumentException("host not allowed");
        }
        response.sendRedirect(next);
    }
}
