// Regression: auth log concat must remain detectable as sink/dataflow candidate
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class R01_AuthLogConcat {
    private static final Logger logger = LoggerFactory.getLogger(R01_AuthLogConcat.class);

    public void login(String user) {
        logger.info("AUTH OK user=" + user);
    }
}
