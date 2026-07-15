import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class P05_StaticCsrfTokenNotBound {
    private static final String CSRF_TOKEN = "fixed-public-token";

    @PostMapping("/settings/email")
    public String updateEmail(@RequestHeader(value = "X-CSRF-TOKEN", required = false) String token,
                              @RequestParam String email) {
        if (token == null || !CSRF_TOKEN.equals(token)) {
            return "forbidden";
        }
        // token is static and not bound to session
        return "email:" + email;
    }
}
