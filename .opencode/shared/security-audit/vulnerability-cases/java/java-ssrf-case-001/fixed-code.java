import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import java.util.Map;

@RestController
public class ProxyController {
    private final RestTemplate restTemplate = new RestTemplate();
    private static final Map<String, String> ALLOWED = Map.of(
        "status", "https://status.example.com/health",
        "docs", "https://docs.example.com/openapi.json"
    );

    @GetMapping("/api/proxy")
    public String proxy(@RequestParam String destinationId) {
        String url = ALLOWED.get(destinationId);
        if (url == null) {
            throw new IllegalArgumentException("unknown destination");
        }
        return restTemplate.getForObject(url, String.class);
    }
}
