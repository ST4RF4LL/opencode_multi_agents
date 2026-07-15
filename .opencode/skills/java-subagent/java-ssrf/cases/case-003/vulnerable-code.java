import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;

@RestController
public class WebhookController {
    private final OkHttpClient client = new OkHttpClient.Builder()
        .followRedirects(true)
        .build();

    public static class WebhookRequest {
        public String callbackUrl;
    }

    @PostMapping("/api/webhook/dispatch")
    public String dispatch(@RequestBody WebhookRequest body) throws IOException {
        Request request = new Request.Builder()
            .url(body.callbackUrl)
            .get()
            .build();
        try (Response response = client.newCall(request).execute()) {
            return response.body() != null ? response.body().string() : "";
        }
    }
}
