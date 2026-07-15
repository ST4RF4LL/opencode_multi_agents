import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class ProxyController {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/api/proxy")
    public String proxy(@RequestParam String url) {
        return restTemplate.getForObject(url, String.class);
    }
}
