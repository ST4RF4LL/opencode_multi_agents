import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class P01_Slf4jConcat {
    private static final Logger logger = LoggerFactory.getLogger(P01_Slf4jConcat.class);

    public void vulnerable(String username) {
        logger.info("Login success for user: " + username);
    }
}
