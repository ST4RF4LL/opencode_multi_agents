import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class P03_Log4j2Concat {
    private static final Logger logger = LogManager.getLogger(P03_Log4j2Concat.class);

    public void vulnerable(String orderId) {
        logger.error("Order failed: " + orderId);
    }
}
