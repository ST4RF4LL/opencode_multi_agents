import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class N03_constant_redirect {
    public void safe(HttpServletResponse response) throws IOException {
        response.sendRedirect("/app/home");
    }
}
