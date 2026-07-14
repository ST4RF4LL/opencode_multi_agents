import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class P05_ModelToRawView {
    @GetMapping("/greet")
    public String greet(@RequestParam("name") String name, Model model) {
        model.addAttribute("name", name);
        return "greet"; // view uses unescaped ${name} or th:utext
    }
}
