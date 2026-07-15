import org.springframework.web.client.RestTemplate;
import java.net.InetAddress;
import java.net.URI;
import java.util.Set;

public class N05_ResolvedIpAllowlist {
    private final RestTemplate restTemplate = new RestTemplate();
    private static final Set<String> ALLOWED_HOSTS = Set.of("public-api.example.com");

    public String safe(String urlString) throws Exception {
        URI uri = URI.create(urlString);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            throw new IllegalArgumentException("invalid scheme or host");
        }
        if (!ALLOWED_HOSTS.contains(uri.getHost().toLowerCase())) {
            throw new IllegalArgumentException("host not allowed");
        }
        for (InetAddress addr : InetAddress.getAllByName(uri.getHost())) {
            if (addr.isAnyLocalAddress()
                || addr.isLoopbackAddress()
                || addr.isLinkLocalAddress()
                || addr.isSiteLocalAddress()) {
                throw new IllegalArgumentException("resolved address not allowed");
            }
        }
        return restTemplate.getForObject(uri, String.class);
    }
}
