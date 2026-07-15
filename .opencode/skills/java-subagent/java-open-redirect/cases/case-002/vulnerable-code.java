import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
    @GetMapping("/login/success")
    public String success(@RequestParam String returnUrl) {
        return "redirect:" + returnUrl;
    }
}
