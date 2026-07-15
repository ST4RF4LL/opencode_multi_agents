import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Regression: classic sendRedirect(userParam) must remain a sink candidate.
 * Must not regress to false negative on full-url-redirect.
 */
public class R01 extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String url = request.getParameter("url");
        response.sendRedirect(url);
    }
}
