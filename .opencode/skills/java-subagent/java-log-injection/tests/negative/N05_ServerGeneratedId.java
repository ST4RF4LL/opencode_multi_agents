import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.UUID;

public class N05_ServerGeneratedId {
    private static final Logger logger = LoggerFactory.getLogger(N05_ServerGeneratedId.class);

    public void safe() {
        String requestId = UUID.randomUUID().toString();
        logger.info("requestId={}", requestId);
    }
}
