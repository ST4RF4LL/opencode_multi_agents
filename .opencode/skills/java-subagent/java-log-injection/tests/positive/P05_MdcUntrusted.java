import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

public class P05_MdcUntrusted {
    private static final Logger logger = LoggerFactory.getLogger(P05_MdcUntrusted.class);

    public void vulnerable(String userId) {
        MDC.put("user", userId);
        logger.info("request processed");
        MDC.remove("user");
    }
}
