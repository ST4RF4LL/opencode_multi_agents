import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class N01_ParameterizedConstant {
    private static final Logger logger = LoggerFactory.getLogger(N01_ParameterizedConstant.class);

    public void safe(String username) {
        String cleaned = username == null ? "" : username.replace("\r", "").replace("\n", "");
        logger.info("Login success for user: {}", cleaned);
    }
}
