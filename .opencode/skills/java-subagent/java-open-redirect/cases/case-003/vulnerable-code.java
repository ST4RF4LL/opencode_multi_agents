import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ContinueServlet extends HttpServlet {
    private static final String TRUSTED_PREFIX = "https://app.example.com";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String next = request.getParameter("next");
        if (next == null || !next.startsWith(TRUSTED_PREFIX)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid next");
            return;
        }
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", next);
    }
}
