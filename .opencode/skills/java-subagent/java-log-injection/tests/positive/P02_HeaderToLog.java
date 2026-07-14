import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;

public class P02_HeaderToLog {
    private static final Logger logger = LoggerFactory.getLogger(P02_HeaderToLog.class);

    public void vulnerable(HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        logger.warn("Client UA=" + ua);
    }
}
