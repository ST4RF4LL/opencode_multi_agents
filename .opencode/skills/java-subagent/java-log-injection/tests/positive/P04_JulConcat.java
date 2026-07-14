import java.util.logging.Logger;

public class P04_JulConcat {
    private static final Logger logger = Logger.getLogger(P04_JulConcat.class.getName());

    public void vulnerable(String input) {
        logger.info("Received: " + input);
    }
}
