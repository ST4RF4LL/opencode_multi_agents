import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class P04_MissingCsrfTokenFormPost {
    @PostMapping("/transfer")
    public String transfer(HttpServletRequest request,
                           @RequestParam String toAccount,
                           @RequestParam long amount) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("user") == null) {
            return "unauthorized";
        }
        // no CSRF token validation before state change
        return "transferred:" + amount + ":" + toAccount;
    }
}
