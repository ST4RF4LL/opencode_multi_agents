import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class ApiClient {
    private final String apiKey;

    public ApiClient(String apiKey) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalArgumentException("API key must be provided via secret manager or env");
        }
        this.apiKey = apiKey;
    }

    public static ApiClient fromEnv() {
        String key = System.getenv("APP_API_KEY");
        return new ApiClient(key);
    }

    public String callRemote(String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.invalid" + path))
            .header("Authorization", "Bearer " + apiKey)
            .header("X-Api-Key", apiKey)
            .GET()
            .build();
        HttpResponse<String> response = HttpClient.newHttpClient()
            .send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}
