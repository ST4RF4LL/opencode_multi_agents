import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class N04_relative_path_enforced {
    @GetMapping("/login/success")
    public String safe(@RequestParam(required = false) String returnUrl) {
        if (returnUrl == null || !isSafeRelativePath(returnUrl)) {
            return "redirect:/app/home";
        }
        return "redirect:" + returnUrl;
    }

    private static boolean isSafeRelativePath(String url) {
        if (!url.startsWith("/") || url.startsWith("//") || url.startsWith("/\\")) {
            return false;
        }
        return !url.contains("://") && !url.contains("\\");
    }
}
