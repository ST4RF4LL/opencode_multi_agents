import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;

public class N04_StructuredStyle {
    private static final Logger logger = LoggerFactory.getLogger(N04_StructuredStyle.class);

    public void safe(String username) {
        String cleaned = username == null ? "" : username.replace("\r", "").replace("\n", "");
        logger.info("event=login_success user={}", cleaned);
    }

    public Map<String, String> asFields(String username) {
        String cleaned = username == null ? "" : username.replace("\r", "").replace("\n", "");
        return Map.of("event", "login_success", "user", cleaned);
    }
}
