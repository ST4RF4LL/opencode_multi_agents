import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Set;

public class ContinueServlet extends HttpServlet {
    private static final Set<String> ALLOWED_HOSTS = Set.of("app.example.com");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String next = request.getParameter("next");
        if (next == null || !isAllowedRedirect(next)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid next");
            return;
        }
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", next);
    }

    private static boolean isAllowedRedirect(String next) {
        try {
            URI uri = URI.create(next);
            if (uri.getScheme() == null || uri.getHost() == null) {
                return false;
            }
            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                return false;
            }
            return ALLOWED_HOSTS.contains(uri.getHost().toLowerCase());
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }
}
