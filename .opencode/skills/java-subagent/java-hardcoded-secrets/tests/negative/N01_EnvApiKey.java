import java.net.URI;
import java.net.http.HttpRequest;

public class N01_EnvApiKey {
    public HttpRequest safe(String path) {
        String apiKey = System.getenv("APP_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("APP_API_KEY required");
        }
        return HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.invalid" + path))
            .header("X-Api-Key", apiKey)
            .GET()
            .build();
    }
}
