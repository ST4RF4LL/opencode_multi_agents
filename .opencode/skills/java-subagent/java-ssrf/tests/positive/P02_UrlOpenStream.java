import java.io.InputStream;
import java.net.URL;

public class P02_UrlOpenStream {
    public InputStream vulnerable(String target) throws Exception {
        URL url = new URL(target);
        return url.openStream();
    }
}
