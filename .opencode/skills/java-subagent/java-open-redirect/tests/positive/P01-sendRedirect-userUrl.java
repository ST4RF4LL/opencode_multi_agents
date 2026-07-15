import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class P01_sendRedirect_userUrl {
    public void vulnerable(HttpServletResponse response, String url) throws IOException {
        response.sendRedirect(url);
    }
}
