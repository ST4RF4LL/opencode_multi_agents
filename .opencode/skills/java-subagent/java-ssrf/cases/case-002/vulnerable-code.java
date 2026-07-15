import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class ResourceController {
    private final RestTemplate restTemplate = new RestTemplate();
    private static final String BASE = "https://trusted.example.com/";

    @GetMapping("/api/resource")
    public String fetch(@RequestParam String path) {
        String url = BASE + path;
        if (!url.startsWith("https://trusted.example.com/")) {
            throw new IllegalArgumentException("invalid url");
        }
        return restTemplate.getForObject(url, String.class);
    }
}
