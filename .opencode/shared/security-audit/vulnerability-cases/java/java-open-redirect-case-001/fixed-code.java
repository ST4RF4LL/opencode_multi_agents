import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

public class RedirectServlet extends HttpServlet {
    private static final Map<String, String> ALLOWED = Map.of(
        "home", "/app/home",
        "profile", "/app/profile",
        "docs", "https://docs.example.com/guide"
    );

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String destinationId = request.getParameter("destinationId");
        String url = ALLOWED.get(destinationId);
        if (url == null) {
            url = "/app/home";
        }
        response.sendRedirect(url);
    }
}
