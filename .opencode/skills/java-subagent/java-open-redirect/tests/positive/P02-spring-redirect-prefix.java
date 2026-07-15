import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class P02_spring_redirect_prefix {
    @GetMapping("/go")
    public String vulnerable(@RequestParam String returnUrl) {
        return "redirect:" + returnUrl;
    }
}
