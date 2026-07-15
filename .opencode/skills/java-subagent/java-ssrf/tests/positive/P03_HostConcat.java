import org.springframework.web.client.RestTemplate;

public class P03_HostConcat {
    private final RestTemplate restTemplate = new RestTemplate();

    public String vulnerable(String host) {
        String url = "http://" + host + "/api/status";
        return restTemplate.getForObject(url, String.class);
    }
}
