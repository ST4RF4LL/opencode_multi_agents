// Pattern: unstructured concat of User-Agent into access log
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class RequestLoggingFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(RequestLoggingFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        String ua = req.getHeader("User-Agent");
        String path = req.getRequestURI();
        logger.info("Access path=" + path + " ua=" + ua);
        chain.doFilter(request, response);
    }
}
