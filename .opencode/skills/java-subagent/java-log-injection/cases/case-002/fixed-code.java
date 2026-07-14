import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class RequestLoggingFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(RequestLoggingFilter.class);
    private static final int MAX_UA_LEN = 256;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        String ua = sanitizeForLog(req.getHeader("User-Agent"), MAX_UA_LEN);
        String path = sanitizeForLog(req.getRequestURI(), 512);
        logger.info("Access path={} ua={}", path, ua);
        chain.doFilter(request, response);
    }

    private static String sanitizeForLog(String value, int maxLen) {
        if (value == null) {
            return "";
        }
        String cleaned = value.replace("\r", "").replace("\n", "").replace("\t", " ");
        if (cleaned.length() > maxLen) {
            return cleaned.substring(0, maxLen);
        }
        return cleaned;
    }
}
