import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class N03_SanitizedBeforeLog {
    private static final Logger logger = LoggerFactory.getLogger(N03_SanitizedBeforeLog.class);

    public void safe(String header) {
        logger.info("header={}", stripControls(header));
    }

    private static String stripControls(String value) {
        if (value == null) {
            return "";
        }
        return value.replaceAll("[\\p{Cntrl}]", "");
    }
}
