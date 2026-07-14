// Pattern: CRLF log forging via username concat into auth log line
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;

public class AuthService {
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    public boolean authenticate(HttpServletRequest request) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        boolean ok = checkPassword(username, password);
        if (ok) {
            logger.info("Login success for user: " + username);
        } else {
            logger.warn("Login failed for user: " + username);
        }
        return ok;
    }

    private boolean checkPassword(String username, String password) {
        return password != null && password.length() > 0;
    }
}
