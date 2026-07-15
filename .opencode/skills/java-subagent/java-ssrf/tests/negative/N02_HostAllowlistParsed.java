import org.springframework.web.client.RestTemplate;
import java.net.URI;
import java.util.Set;

public class N02_HostAllowlistParsed {
    private final RestTemplate restTemplate = new RestTemplate();
    private static final Set<String> ALLOWED_HOSTS = Set.of("api.partner.example.com");

    public String safe(String urlString) throws Exception {
        URI uri = URI.create(urlString);
        if (!"https".equalsIgnoreCase(uri.getScheme())
            || uri.getHost() == null
            || !ALLOWED_HOSTS.contains(uri.getHost().toLowerCase())) {
            throw new IllegalArgumentException("host not allowed");
        }
        return restTemplate.getForObject(uri, String.class);
    }
}
