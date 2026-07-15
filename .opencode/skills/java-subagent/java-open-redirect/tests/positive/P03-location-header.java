import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class P03_location_header {
    public void vulnerable(HttpServletResponse response, String next) throws IOException {
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", next);
    }
}
