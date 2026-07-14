import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;

public class AuthService {
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    public boolean authenticate(HttpServletRequest request) {
        String username = sanitizeForLog(request.getParameter("username"));
        String password = request.getParameter("password");
        boolean ok = checkPassword(request.getParameter("username"), password);
        if (ok) {
            logger.info("Login success for user: {}", username);
        } else {
            logger.warn("Login failed for user: {}", username);
        }
        return ok;
    }

    private static String sanitizeForLog(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\r", "").replace("\n", "").replace("\t", "_");
    }

    private boolean checkPassword(String username, String password) {
        return password != null && password.length() > 0;
    }
}
