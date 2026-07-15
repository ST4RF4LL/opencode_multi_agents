import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
    @GetMapping("/login/success")
    public String success(@RequestParam(required = false) String returnUrl) {
        if (returnUrl == null || returnUrl.isEmpty()) {
            return "redirect:/app/home";
        }
        if (!isSafeRelativePath(returnUrl)) {
            return "redirect:/app/home";
        }
        return "redirect:" + returnUrl;
    }

    private static boolean isSafeRelativePath(String url) {
        if (!url.startsWith("/") || url.startsWith("//") || url.startsWith("/\\")) {
            return false;
        }
        if (url.contains("://") || url.contains("\\")) {
            return false;
        }
        return true;
    }
}
