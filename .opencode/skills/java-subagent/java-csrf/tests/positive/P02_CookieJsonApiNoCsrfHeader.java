import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class P02_CookieJsonApiNoCsrfHeader {
    public static class EmailBody {
        public String email;
    }

    @PostMapping(path = "/api/profile/email", consumes = "application/json")
    public String updateEmail(@RequestBody EmailBody body) {
        // session cookie auth assumed; no CSRF header check
        return "updated:" + body.email;
    }
}
