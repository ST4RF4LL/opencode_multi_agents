import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;
import java.util.Set;

@RestController
public class WebhookController {
    private final OkHttpClient client = new OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build();
    private static final Set<String> ALLOWED_HOSTS = Set.of(
        "hooks.partner.example.com",
        "events.partner.example.com"
    );

    public static class WebhookRequest {
        public String callbackUrl;
    }

    @PostMapping("/api/webhook/dispatch")
    public String dispatch(@RequestBody WebhookRequest body) throws IOException {
        HttpUrl url = HttpUrl.parse(body.callbackUrl);
        if (url == null
            || !"https".equalsIgnoreCase(url.scheme())
            || !ALLOWED_HOSTS.contains(url.host().toLowerCase())) {
            throw new IllegalArgumentException("callback not allowed");
        }
        Request request = new Request.Builder()
            .url(url)
            .get()
            .build();
        try (Response response = client.newCall(request).execute()) {
            return response.body() != null ? response.body().string() : "";
        }
    }
}
