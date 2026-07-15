import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import java.net.URI;

@RestController
public class ResourceController {
    private final RestTemplate restTemplate = new RestTemplate();
    private static final String HOST = "trusted.example.com";

    @GetMapping("/api/resource")
    public String fetch(@RequestParam String path) {
        if (path == null || path.contains("..") || path.startsWith("//")) {
            throw new IllegalArgumentException("invalid path");
        }
        URI uri = UriComponentsBuilder.newInstance()
            .scheme("https")
            .host(HOST)
            .path("/" + path.replaceAll("^/+", ""))
            .build(true)
            .toUri();
        if (!HOST.equalsIgnoreCase(uri.getHost()) || !"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("invalid destination");
        }
        return restTemplate.getForObject(uri, String.class);
    }
}
