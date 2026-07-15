import org.springframework.web.client.RestTemplate;

public class N03_ConstantUrl {
    private final RestTemplate restTemplate = new RestTemplate();

    public String safe() {
        return restTemplate.getForObject("https://status.example.com/health", String.class);
    }
}
