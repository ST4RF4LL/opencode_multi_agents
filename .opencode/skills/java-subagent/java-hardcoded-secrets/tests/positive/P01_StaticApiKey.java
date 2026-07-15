import java.net.URI;
import java.net.http.HttpRequest;

public class P01_StaticApiKey {
    private static final String API_KEY = "AKIAIOSFODNN7EXAMPLE";

    public HttpRequest vulnerable(String path) {
        return HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.invalid" + path))
            .header("X-Api-Key", API_KEY)
            .GET()
            .build();
    }
}
