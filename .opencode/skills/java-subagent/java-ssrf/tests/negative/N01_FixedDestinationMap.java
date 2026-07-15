import org.springframework.web.client.RestTemplate;
import java.util.Map;

public class N01_FixedDestinationMap {
    private final RestTemplate restTemplate = new RestTemplate();
    private static final Map<String, String> ALLOWED = Map.of(
        "health", "https://status.example.com/health",
        "openapi", "https://docs.example.com/openapi.json"
    );

    public String safe(String destinationId) {
        String url = ALLOWED.get(destinationId);
        if (url == null) {
            throw new IllegalArgumentException("unknown destination");
        }
        return restTemplate.getForObject(url, String.class);
    }
}
