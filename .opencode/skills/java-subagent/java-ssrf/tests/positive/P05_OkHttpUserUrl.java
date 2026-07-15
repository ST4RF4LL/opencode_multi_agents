import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.io.IOException;

public class P05_OkHttpUserUrl {
    private final OkHttpClient client = new OkHttpClient.Builder()
        .followRedirects(true)
        .build();

    public String vulnerable(String callbackUrl) throws IOException {
        Request request = new Request.Builder()
            .url(callbackUrl)
            .get()
            .build();
        try (Response response = client.newCall(request).execute()) {
            return response.body() != null ? response.body().string() : "";
        }
    }
}
