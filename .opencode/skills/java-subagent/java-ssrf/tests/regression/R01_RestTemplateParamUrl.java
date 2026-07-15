import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class R01_RestTemplateParamUrl {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/api/fetch")
    public String fetch(@RequestParam String url) {
        return restTemplate.exchange(url, org.springframework.http.HttpMethod.GET, null, String.class)
            .getBody();
    }
}
