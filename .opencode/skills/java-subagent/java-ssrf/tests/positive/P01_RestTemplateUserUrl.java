import org.springframework.web.client.RestTemplate;

public class P01_RestTemplateUserUrl {
    private final RestTemplate restTemplate = new RestTemplate();

    public String vulnerable(String url) {
        return restTemplate.getForObject(url, String.class);
    }
}
