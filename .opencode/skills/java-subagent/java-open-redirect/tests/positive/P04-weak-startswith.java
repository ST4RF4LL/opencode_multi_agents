import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class P04_weak_startswith {
    private static final String TRUSTED = "https://app.example.com";

    public void vulnerable(HttpServletResponse response, String next) throws IOException {
        if (!next.startsWith(TRUSTED)) {
            throw new IllegalArgumentException("invalid");
        }
        response.sendRedirect(next);
    }
}
