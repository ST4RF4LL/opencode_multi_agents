import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Set;

public class N04_SchemeDenyNonHttp {
    private final HttpClient client = HttpClient.newHttpClient();
    private static final Set<String> ALLOWED_SCHEMES = Set.of("https");
    private static final Set<String> ALLOWED_HOSTS = Set.of("cdn.example.com");

    public String safe(String urlString) throws Exception {
        URI uri = URI.create(urlString);
        if (!ALLOWED_SCHEMES.contains(uri.getScheme() == null ? "" : uri.getScheme().toLowerCase())
            || uri.getHost() == null
            || !ALLOWED_HOSTS.contains(uri.getHost().toLowerCase())) {
            throw new IllegalArgumentException("destination not allowed");
        }
        HttpRequest request = HttpRequest.newBuilder(uri).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
}
