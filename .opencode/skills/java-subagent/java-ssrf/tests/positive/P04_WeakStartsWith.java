import org.springframework.web.client.RestTemplate;

public class P04_WeakStartsWith {
    private final RestTemplate restTemplate = new RestTemplate();
    private static final String BASE = "https://trusted.example.com/";

    public String vulnerable(String path) {
        String url = BASE + path;
        if (!url.startsWith("https://trusted.example.com/")) {
            throw new IllegalArgumentException("invalid");
        }
        return restTemplate.getForObject(url, String.class);
    }
}
