// Pattern: static final API key constant used for outbound auth
// Sample key is AWS docs example only (not a real credential).
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class ApiClient {
    private static final String API_KEY = "AKIAIOSFODNN7EXAMPLE";

    public String callRemote(String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.invalid" + path))
            .header("Authorization", "Bearer " + API_KEY)
            .header("X-Api-Key", API_KEY)
            .GET()
            .build();
        HttpResponse<String> response = HttpClient.newHttpClient()
            .send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}
