import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

public class N01_fixed_destination_map {
    private static final Map<String, String> ALLOWED = Map.of(
        "home", "/app/home",
        "docs", "https://docs.example.com/guide"
    );

    public void safe(HttpServletResponse response, String destinationId) throws IOException {
        String url = ALLOWED.get(destinationId);
        if (url == null) {
            url = "/app/home";
        }
        response.sendRedirect(url);
    }
}
