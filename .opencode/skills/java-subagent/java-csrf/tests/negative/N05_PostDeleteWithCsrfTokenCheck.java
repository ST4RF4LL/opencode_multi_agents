import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class N05_PostDeleteWithCsrfTokenCheck {
    @PostMapping("/items/delete")
    public String delete(HttpSession session,
                         @RequestParam long id,
                         @RequestParam("_csrf") String csrf) {
        Object expected = session.getAttribute("CSRF_TOKEN");
        if (expected == null || !expected.toString().equals(csrf)) {
            return "forbidden";
        }
        return "deleted:" + id;
    }
}
