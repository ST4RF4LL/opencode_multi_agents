// Pattern: Spring MVC puts request param into model; JSP EL prints unescaped
// Companion view: search.jsp uses ${q} without c:out
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class SearchController {
    @GetMapping("/search")
    public String search(@RequestParam("q") String q, Model model) {
        model.addAttribute("q", q);
        return "search";
    }
}

/*
// search.jsp (vulnerable)
<html>
<body>
  <p>Results for: ${q}</p>
</body>
</html>
*/
